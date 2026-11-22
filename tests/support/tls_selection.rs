#[path = "packets.rs"]
mod packets;

use packrat_tui::net::{packet::Packet, parser::parse_ethernet};

pub fn server_hello(version: u16, cipher: u16, extensions: &[u8]) -> Vec<u8> {
    let mut body = version.to_be_bytes().to_vec();
    body.extend([0x7f; 32]);
    body.push(0); // Session ID length.
    body.extend(cipher.to_be_bytes());
    body.push(0); // No compression.
    if !extensions.is_empty() {
        body.extend((extensions.len() as u16).to_be_bytes());
        body.extend(extensions);
    }
    let mut record = vec![0x16, 3, 1]; // Record version does not identify the selected version.
    record.extend(((body.len() + 4) as u16).to_be_bytes());
    record.extend([2, 0, 0, body.len() as u8]);
    record.extend(body);
    record
}

pub fn tls_packet(
    no: u64,
    sequence: u32,
    flags: u8,
    source: u16,
    destination: u16,
    payload: &[u8],
) -> Packet {
    let mut raw = packets::tcp(no, sequence, flags, payload).bytes;
    raw[34..36].copy_from_slice(&source.to_be_bytes());
    raw[36..38].copy_from_slice(&destination.to_be_bytes());
    parse_ethernet(&raw, no, no as f64)
}

pub fn tls_segment(no: u64, sequence: u32, flags: u8, payload: &[u8]) -> Packet {
    tls_packet(no, sequence, flags, 8443, 50000, payload)
}
