use packrat_tui::net::{packet::Packet, parser::parse_ethernet};

pub fn invalid_neighbor_discovery_hop_limit(no: u64) -> Packet {
    let mut bytes = [0_u8; 62];
    bytes[..6].copy_from_slice(&[0x33, 0x33, 0, 0, 0, 2]);
    bytes[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    bytes[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
    bytes[14] = 0x60;
    bytes[18..20].copy_from_slice(&8_u16.to_be_bytes());
    bytes[20] = 58;
    bytes[21] = 64;
    bytes[22..24].copy_from_slice(&[0xfe, 0x80]);
    bytes[37] = 1;
    bytes[38..40].copy_from_slice(&[0xff, 2]);
    bytes[53] = 2;
    bytes[54] = 133;
    parse_ethernet(&bytes, no, no as f64)
}
