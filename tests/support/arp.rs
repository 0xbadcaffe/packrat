use packrat_tui::net::{packet::Packet, parser::parse_ethernet};

pub fn reply(frame: u64, time: f64, vlan: u16, host: u8) -> Packet {
    let sender = [2, 0, 0, 0, 0, host];
    let receiver = [2, 0, 0, 0, 0, 99];
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&receiver);
    bytes.extend_from_slice(&sender);
    bytes.extend_from_slice(&0x8100_u16.to_be_bytes());
    bytes.extend_from_slice(&vlan.to_be_bytes());
    bytes.extend_from_slice(&0x0806_u16.to_be_bytes());
    bytes.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 2]);
    bytes.extend_from_slice(&sender);
    bytes.extend_from_slice(&[192, 0, 2, 1]);
    bytes.extend_from_slice(&receiver);
    bytes.extend_from_slice(&[192, 0, 2, 99]);
    parse_ethernet(&bytes, frame, time)
}
