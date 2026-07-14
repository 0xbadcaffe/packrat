//! Privilege-separated capture helper protocol and client.

use std::io::{self, Write};
use std::path::PathBuf;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use crate::capture::CaptureSource;
use crate::net::packet::Packet;
use crate::net::parser::parse_ethernet;

pub const MAX_CAPTURE_FRAME: usize = 1_048_576;
const HEADER_LENGTH: usize = 12;

pub struct HelperCapture {
    pub program: PathBuf,
    pub iface: String,
    pub filter: Option<String>,
}

impl CaptureSource for HelperCapture {
    fn run(self, tx: Sender<Packet>) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut command = tokio::process::Command::new(&self.program);
            command.arg("--interface").arg(&self.iface)
                .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null()).kill_on_drop(true);
            if let Some(filter) = self.filter { command.arg("--filter").arg(filter); }
            let Ok(mut child) = command.spawn() else { return; };
            let Some(mut output) = child.stdout.take() else { return; };
            let mut packet_no = 0_u64;
            loop {
                let mut header = [0_u8; HEADER_LENGTH];
                if output.read_exact(&mut header).await.is_err() { break; }
                let timestamp_micros = u64::from_be_bytes(header[..8].try_into().unwrap());
                let length = u32::from_be_bytes(header[8..].try_into().unwrap()) as usize;
                if length == 0 || length > MAX_CAPTURE_FRAME { break; }
                let mut frame = vec![0_u8; length];
                if output.read_exact(&mut frame).await.is_err() { break; }
                packet_no += 1;
                let packet = parse_ethernet(&frame, packet_no, timestamp_micros as f64 / 1_000_000.0);
                if tx.send(packet).await.is_err() { break; }
            }
            let _ = child.kill().await;
        })
    }
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
