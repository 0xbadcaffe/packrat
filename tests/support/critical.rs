use packrat_tui::net::{packet::Packet, parser::parse_ethernet};

#[path = "packets.rs"]
mod packets;

pub fn http_framing_ambiguity(no: u64) -> Packet {
    let mut packet = packets::tcp(
        no,
        100,
        0x18,
        b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n",
    );
    // Independent connections let delivery tests fill IDS history with distinct samples.
    packet.bytes[34..36].copy_from_slice(&(10_000 + (no % 40_000) as u16).to_be_bytes());
    parse_ethernet(&packet.bytes, no, no as f64)
}
