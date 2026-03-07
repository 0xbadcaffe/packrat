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
        hdr.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic
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
        let ts_sec = pkt.timestamp as u32;
        let ts_usec = ((pkt.timestamp.fract()) * 1_000_000.0) as u32;
        let cap_len = pkt.bytes.len() as u32;

        let mut rec = Vec::with_capacity(16 + pkt.bytes.len());
        rec.extend_from_slice(&ts_sec.to_le_bytes());
        rec.extend_from_slice(&ts_usec.to_le_bytes());
        rec.extend_from_slice(&cap_len.to_le_bytes());
        rec.extend_from_slice(&cap_len.to_le_bytes()); // orig_len == cap_len
        rec.extend_from_slice(&pkt.bytes);
        self.writer.write_all(&rec)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush().map_err(Into::into)
    }
}
