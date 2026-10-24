use packrat_tui::net::packet::Packet;
use packrat_tui::net::parser::parse_ethernet;

pub fn tcp(no: u64, sequence: u32, flags: u8, payload: &[u8]) -> Packet {
    let mut bytes = vec![0; 54];
    bytes[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    bytes[22] = 64;
    bytes[23] = 6;
    bytes[26..30].copy_from_slice(&[10, 0, 0, 1]);
    bytes[30..34].copy_from_slice(&[10, 0, 0, 2]);
    bytes[34..36].copy_from_slice(&40_000u16.to_be_bytes());
    bytes[36..38].copy_from_slice(&80u16.to_be_bytes());
    bytes[38..42].copy_from_slice(&sequence.to_be_bytes());
    bytes[46] = 0x50;
    bytes[47] = flags;
    bytes.extend_from_slice(payload);
    parse_ethernet(&bytes, no, no as f64)
}
