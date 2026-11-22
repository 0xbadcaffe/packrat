use packrat_tui::net::{packet::Packet, parser::parse_ethernet};

pub fn fixture(no: u64, pid: u16, vlan: Option<u16>) -> Packet {
    let mut bytes = vec![1, 0, 0x0c, 0xcc, 0xcc, 0xcc, 2, 0, 0, 0, 0, 7];
    if let Some(tag) = vlan {
        bytes.extend_from_slice(&0x8100_u16.to_be_bytes());
        bytes.extend_from_slice(&tag.to_be_bytes());
    }
    let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0x0c];
    body.extend_from_slice(&pid.to_be_bytes());
    body.extend_from_slice(&[1, 0, 2, 0, 5, 4]);
    bytes.extend_from_slice(&(body.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&body);
    bytes.resize(60, 0); // Ethernet padding must not be parsed as a TLV.
    parse_ethernet(&bytes, no, no as f64)
}
