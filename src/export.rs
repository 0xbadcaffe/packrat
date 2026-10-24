use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::Result;
use crate::net::packet::Packet;

/// Writes captured packets to a libpcap-format `.pcap` file.
pub struct PcapWriter {
    writer: BufWriter<File>,
}

impl PcapWriter {
    /// Creates the file and writes the global pcap header.
    pub fn new(path: &Path) -> Result<Self> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        // Global header (little-endian)
        // magic | ver_major | ver_minor | thiszone | sigfigs | snaplen | network
        let mut hdr = Vec::with_capacity(24);
        hdr.extend_from_slice(&0xa1b23c4du32.to_le_bytes()); // nanosecond precision
        hdr.extend_from_slice(&2u16.to_le_bytes());           // major version
        hdr.extend_from_slice(&4u16.to_le_bytes());           // minor version
        hdr.extend_from_slice(&0i32.to_le_bytes());           // UTC timezone
        hdr.extend_from_slice(&0u32.to_le_bytes());           // timestamp accuracy
        hdr.extend_from_slice(&65535u32.to_le_bytes());       // snaplen
        hdr.extend_from_slice(&1u32.to_le_bytes());           // LINKTYPE_ETHERNET
        writer.write_all(&hdr)?;

        Ok(Self { writer })
    }

    /// Appends one packet record.
    pub fn write_packet(&mut self, pkt: &Packet) -> Result<()> {
        let timestamp_ns = if let Some(capture) = &pkt.capture {
            anyhow::ensure!(capture.link_type == 1, "Classic export requires Ethernet packets; use PCAPNG for other link types");
            anyhow::ensure!(capture.captured_length as usize == pkt.bytes.len(), "Captured length does not match packet bytes");
            anyhow::ensure!(capture.wire_length >= capture.captured_length, "Invalid wire length");
            capture.timestamp.ok_or_else(|| anyhow::anyhow!("Packet has no capture timestamp"))?.nanoseconds()
        } else {
            anyhow::ensure!(pkt.timestamp.is_finite() && pkt.timestamp >= 0.0, "Invalid packet timestamp");
            (pkt.timestamp * 1_000_000_000.0).round() as i128
        };
        anyhow::ensure!(timestamp_ns >= 0 && timestamp_ns / 1_000_000_000 <= i128::from(u32::MAX), "Timestamp is outside classic PCAP range");
        let ts_sec = (timestamp_ns / 1_000_000_000) as u32;
        let ts_fraction = (timestamp_ns % 1_000_000_000) as u32;
        anyhow::ensure!(pkt.bytes.len() <= 65535, "Packet exceeds classic export snapshot length");
        let cap_len = pkt.bytes.len() as u32;
        let wire_len = pkt.capture.as_ref().map_or(cap_len, |capture| capture.wire_length);

        let mut rec = Vec::with_capacity(16 + pkt.bytes.len());
        rec.extend_from_slice(&ts_sec.to_le_bytes());
        rec.extend_from_slice(&ts_fraction.to_le_bytes());
        rec.extend_from_slice(&cap_len.to_le_bytes());
        rec.extend_from_slice(&wire_len.to_le_bytes());
        rec.extend_from_slice(&pkt.bytes);
        self.writer.write_all(&rec)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush().map_err(Into::into)
    }
}
