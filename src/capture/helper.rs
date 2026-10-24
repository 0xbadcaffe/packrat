//! Privilege-separated capture helper protocol and client.

use std::io::{self, Write};
use std::path::PathBuf;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc::Sender;
use crate::capture::{CaptureSource, CaptureTask};
use crate::net::packet::{Packet, CaptureMetadata, CaptureTimestamp, TimestampResolution};
use crate::net::parser::{parse_ethernet, parse_captured};

pub const MAX_CAPTURE_FRAME: usize = 1_048_576;
const HEADER_LENGTH: usize = 12;
const V2_MAGIC: &[u8; 4] = b"PKT2";
const V2_HEADER: usize = 40;

pub struct HelperCapture {
    pub program: PathBuf,
    pub iface: String,
    pub filter: Option<String>,
}

impl CaptureSource for HelperCapture {
    fn run(self, tx: Sender<Packet>) -> CaptureTask {
        CaptureTask::spawn(async move {
            let mut command = tokio::process::Command::new(&self.program);
            command.arg("--interface").arg(&self.iface)
                .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null()).kill_on_drop(true);
            if let Some(filter) = self.filter { command.arg("--filter").arg(filter); }
            let mut child = command.spawn().map_err(|error| format!("Start capture helper: {error}"))?;
            let mut output = child.stdout.take().ok_or("Capture helper stdout unavailable")?;
            let mut packet_no = 0_u64;
            loop {
                let mut header = [0_u8; V2_HEADER];
                output.read_exact(&mut header[..4]).await.map_err(|error| format!("Capture helper header: {error}"))?;
                let version_two = &header[..4] == V2_MAGIC;
                let header_length = if version_two { V2_HEADER } else { HEADER_LENGTH };
                output.read_exact(&mut header[4..header_length]).await.map_err(|error| format!("Capture helper header: {error}"))?;
                let position = if version_two { 24 } else { 8 };
                let length = u32::from_be_bytes(header[position..position + 4].try_into().unwrap()) as usize;
                if length == 0 || length > MAX_CAPTURE_FRAME { return Err("Invalid capture helper frame length".into()); }
                let mut encoded = vec![0_u8; header_length + length];
                encoded[..header_length].copy_from_slice(&header[..header_length]);
                output.read_exact(&mut encoded[header_length..]).await.map_err(|error| format!("Capture helper payload: {error}"))?;
                packet_no += 1;
                let packet = if version_two {
                    let (mut metadata, data) = decode_capture_frame(&encoded)?;
                    metadata.interface_name = Some(self.iface.clone());
                    parse_captured(data, packet_no, metadata)?
                } else {
                    let (timestamp_micros, data) = decode_frame(&encoded)?;
                    parse_ethernet(data, packet_no, timestamp_micros as f64 / 1_000_000.0)
                };
                if tx.send(packet).await.is_err() { break; }
            }
            let _ = child.kill().await;
            Ok(())
        })
    }
}

pub fn write_capture_frame(mut output: impl Write, capture: &CaptureMetadata, frame: &[u8]) -> io::Result<()> {
    let invalid = |message| io::Error::new(io::ErrorKind::InvalidInput, message);
    if frame.is_empty() || frame.len() > MAX_CAPTURE_FRAME || capture.captured_length as usize != frame.len() || capture.wire_length < capture.captured_length {
        return Err(invalid("Invalid captured packet lengths"));
    }
    let timestamp = capture.timestamp.ok_or_else(|| invalid("Capture helper requires a timestamp"))?;
    let resolution = match timestamp.resolution {
        TimestampResolution::Decimal(value) if value < 128 => value,
        TimestampResolution::Binary(value) if value < 128 => value | 0x80,
        _ => return Err(invalid("Unsupported helper timestamp resolution")),
    };
    let mut header = [0u8; V2_HEADER];
    header[..4].copy_from_slice(V2_MAGIC);
    header[4..12].copy_from_slice(&timestamp.offset_seconds.to_be_bytes());
    header[12..20].copy_from_slice(&timestamp.ticks.to_be_bytes());
    header[20] = resolution;
    for (offset, value) in [(24, capture.captured_length), (28, capture.wire_length), (32, capture.link_type), (36, capture.interface_id)] {
        header[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    output.write_all(&header)?;
    output.write_all(frame)?;
    output.flush()
}

pub fn decode_capture_frame(bytes: &[u8]) -> Result<(CaptureMetadata, &[u8]), String> {
    if bytes.len() < V2_HEADER || &bytes[..4] != V2_MAGIC {
        return Err("Invalid version-two capture helper header".into());
    }
    if bytes[21..24] != [0, 0, 0] { return Err("Unsupported capture helper flags".into()); }
    let read = |offset| u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let length = read(24);
    let wire_length = read(28);
    if length == 0 || length as usize > MAX_CAPTURE_FRAME || wire_length < length || bytes.len() != V2_HEADER + length as usize {
        return Err("Invalid version-two capture helper payload length".into());
    }
    let metadata = CaptureMetadata {
        timestamp: Some(CaptureTimestamp {
            offset_seconds: i64::from_be_bytes(bytes[4..12].try_into().unwrap()),
            ticks: u64::from_be_bytes(bytes[12..20].try_into().unwrap()),
            resolution: if bytes[20] & 0x80 != 0 { TimestampResolution::Binary(bytes[20] & 0x7f) } else { TimestampResolution::Decimal(bytes[20]) },
        }),
        captured_length: length,
        wire_length,
        link_type: read(32),
        interface_id: read(36),
        section_id: 0,
        interface_name: None,
        comments: Vec::new(),
    };
    Ok((metadata, &bytes[V2_HEADER..]))
}

pub fn write_frame(mut output: impl Write, timestamp_micros: u64, frame: &[u8]) -> io::Result<()> {
    if frame.is_empty() || frame.len() > MAX_CAPTURE_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "capture frame length is invalid"));
    }
    output.write_all(&timestamp_micros.to_be_bytes())?;
    output.write_all(&(frame.len() as u32).to_be_bytes())?;
    output.write_all(frame)?;
    output.flush()
}

pub fn decode_frame(bytes: &[u8]) -> Result<(u64, &[u8]), String> {
    if bytes.len() < HEADER_LENGTH { return Err("capture helper frame header is truncated".into()); }
    let timestamp = u64::from_be_bytes(bytes[..8].try_into().unwrap());
    let length = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if length == 0 || length > MAX_CAPTURE_FRAME { return Err("capture helper frame length is invalid".into()); }
    let end = HEADER_LENGTH.checked_add(length).ok_or("capture helper frame length overflow")?;
    if bytes.len() != end { return Err("capture helper frame payload length does not match header".into()); }
    Ok((timestamp, &bytes[HEADER_LENGTH..end]))
}
