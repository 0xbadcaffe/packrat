//! Streaming PCAPNG output. Interface numbers are local to the output section.

use crate::net::packet::{CaptureMetadata, CaptureTimestamp, Packet, TimestampResolution};
use anyhow::{Result, ensure};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

#[derive(PartialEq, Eq)]
struct Interface {
    source_id: u32,
    link_type: u32,
    name: Option<String>,
    resolution: TimestampResolution,
    offset: i64,
}

pub struct PcapNgWriter<W: Write> {
    writer: W,
    source_section: Option<u32>,
    interfaces: Vec<Interface>,
}

impl PcapNgWriter<BufWriter<File>> {
    /// Never overwrite existing evidence; new captures are private on Unix.
    pub fn create(path: &Path) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        Ok(Self::new(BufWriter::new(options.open(path)?)))
    }
}

impl<W: Write> PcapNgWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            source_section: None,
            interfaces: Vec::new(),
        }
    }

    fn block(&mut self, kind: u32, mut body: Vec<u8>) -> Result<()> {
        body.resize((body.len() + 3) & !3, 0);
        let length = u32::try_from(body.len() + 12)?;
        self.writer.write_all(&kind.to_le_bytes())?;
        self.writer.write_all(&length.to_le_bytes())?;
        self.writer.write_all(&body)?;
        self.writer.write_all(&length.to_le_bytes())?;
        Ok(())
    }

    fn section(&mut self, source: u32) -> Result<()> {
        let mut body = 0x1a2b3c4du32.to_le_bytes().to_vec();
        body.extend(1u16.to_le_bytes());
        body.extend(0u16.to_le_bytes());
        body.extend((-1i64).to_le_bytes());
        self.block(0x0a0d0d0a, body)?;
        self.source_section = Some(source);
        self.interfaces.clear();
        Ok(())
    }

    fn interface(&mut self, interface: Interface, snaplen: u32) -> Result<u32> {
        if let Some(index) = self.interfaces.iter().position(|entry| *entry == interface) {
            return Ok(index as u32);
        }
        ensure!(
            self.interfaces.len() < 4096,
            "PCAPNG interface limit reached"
        );
        let mut body = (interface.link_type as u16).to_le_bytes().to_vec();
        body.extend(0u16.to_le_bytes());
        body.extend(snaplen.to_le_bytes());
        if let Some(name) = &interface.name {
            option(&mut body, 2, name.as_bytes());
        }
        let resolution = match interface.resolution {
            TimestampResolution::Decimal(value) => value,
            TimestampResolution::Binary(value) => value | 0x80,
        };
        option(&mut body, 9, &[resolution]);
        option(&mut body, 14, &interface.offset.to_le_bytes());
        option(&mut body, 0, &[]);
        self.block(1, body)?;
        let index = self.interfaces.len() as u32;
        self.interfaces.push(interface);
        Ok(index)
    }

    pub fn write_packet(&mut self, packet: &Packet) -> Result<()> {
        ensure!(
            packet.bytes.len() <= 1_048_576,
            "Packet exceeds export length limit"
        );
        let fallback;
        let capture = if let Some(capture) = &packet.capture {
            capture
        } else {
            ensure!(
                packet.timestamp.is_finite() && packet.timestamp >= 0.0,
                "Invalid legacy packet timestamp"
            );
            let ticks = (packet.timestamp * 1_000_000_000.0).round();
            ensure!(
                ticks < u64::MAX as f64,
                "Legacy timestamp is outside export range"
            );
            fallback = CaptureMetadata {
                timestamp: Some(CaptureTimestamp {
                    ticks: ticks as u64,
                    resolution: TimestampResolution::Decimal(9),
                    offset_seconds: 0,
                }),
                captured_length: packet.bytes.len() as u32,
                wire_length: packet.bytes.len() as u32,
                link_type: 1,
                interface_id: 0,
                section_id: 0,
                interface_name: None,
                comments: Vec::new(),
            };
            &fallback
        };
        ensure!(
            capture.captured_length as usize == packet.bytes.len()
                && capture.wire_length >= capture.captured_length,
            "Invalid capture lengths"
        );
        ensure!(
            capture.link_type <= u16::MAX as u32,
            "Link type is outside PCAPNG range"
        );
        ensure!(
            capture
                .interface_name
                .as_ref()
                .is_none_or(|name| name.len() <= 4096),
            "Interface name exceeds export limit"
        );
        ensure!(
            capture.comments.len() <= 16
                && capture.comments.iter().all(|comment| comment.len() <= 4096),
            "Packet comments exceed export limits"
        );
        let clock = capture.timestamp.unwrap_or(CaptureTimestamp {
            ticks: 0,
            resolution: TimestampResolution::Decimal(6),
            offset_seconds: 0,
        });
        let exponent = match clock.resolution {
            TimestampResolution::Decimal(value) | TimestampResolution::Binary(value) => value,
        };
        ensure!(exponent <= 127, "Clock resolution is outside PCAPNG range");
        if capture.timestamp.is_none() {
            ensure!(
                capture.comments.is_empty(),
                "Untimed simple packets cannot carry comments"
            );
            ensure!(
                capture.captured_length != 0 || capture.wire_length == 0,
                "An empty truncated untimed packet cannot be represented in PCAPNG"
            );
        }

        // Untimed packets require interface zero, with a snaplen describing
        // their actual retained bytes. Isolate them rather than invent a clock.
        if capture.timestamp.is_none() || self.source_section != Some(capture.section_id) {
            self.section(capture.section_id)?;
        }
        let interface = Interface {
            source_id: capture.interface_id,
            link_type: capture.link_type,
            name: capture.interface_name.clone(),
            resolution: clock.resolution,
            offset: clock.offset_seconds,
        };
        let interface_id = self.interface(
            interface,
            if capture.timestamp.is_none() {
                capture.captured_length
            } else {
                1_048_576
            },
        )?;
        if capture.timestamp.is_none() {
            let mut body = capture.wire_length.to_le_bytes().to_vec();
            body.extend(&packet.bytes);
            self.block(3, body)?;
            self.source_section = None;
        } else {
            let mut body = Vec::with_capacity(24 + packet.bytes.len());
            for value in [
                interface_id,
                (clock.ticks >> 32) as u32,
                clock.ticks as u32,
                capture.captured_length,
                capture.wire_length,
            ] {
                body.extend(value.to_le_bytes());
            }
            body.extend(&packet.bytes);
            body.resize((body.len() + 3) & !3, 0);
            for comment in &capture.comments {
                option(&mut body, 1, comment.as_bytes());
            }
            option(&mut body, 0, &[]);
            self.block(6, body)?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        if self.source_section.is_none() && self.interfaces.is_empty() {
            self.section(0)?;
        }
        self.writer.flush().map_err(Into::into)
    }
}

fn option(body: &mut Vec<u8>, code: u16, value: &[u8]) {
    body.extend(code.to_le_bytes());
    body.extend((value.len() as u16).to_le_bytes());
    body.extend(value);
    body.resize((body.len() + 3) & !3, 0);
}
