use packrat_tui::analysis::packet_compare::{compare, FieldDifferenceKind};
use packrat_tui::net::packet::Packet;

fn packet(no: u64, sequence: u32, payload: &[u8]) -> Packet {
    let mut bytes = vec![0_u8; 14 + 20 + 20];
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    bytes[23] = 6;
    bytes[34..36].copy_from_slice(&50_000_u16.to_be_bytes());
    bytes[36..38].copy_from_slice(&443_u16.to_be_bytes());
    bytes[38..42].copy_from_slice(&sequence.to_be_bytes());
    bytes[46] = 0x50;
    bytes.extend_from_slice(payload);
    Packet {
        no,
        timestamp: no as f64,
        src: "192.0.2.1".into(),
        dst: "198.51.100.2".into(),
        protocol: "TCP".into(),
        length: bytes.len() as u16,
        info: String::new(),
        src_port: Some(50_000),
        dst_port: Some(443),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes,
    }
}

#[test]
fn compares_decoded_fields_and_captured_bytes() {
    let left = packet(1, 100, b"hello");
    let right = packet(2, 105, b"hullo!");
    let result = compare(&left, &right);
    let sequence = result
        .field_differences
        .iter()
        .find(|difference| difference.path == "tcp.seq")
        .unwrap();
    assert_eq!(sequence.kind, FieldDifferenceKind::Changed);
    assert_eq!(sequence.left.as_deref(), Some("100"));
    assert_eq!(sequence.right.as_deref(), Some("105"));
    assert!(result.first_byte_difference.is_some());
    assert_eq!(result.left_length + 1, result.right_length);
}

#[test]
fn identical_packets_have_no_structural_or_byte_differences() {
    let left = packet(1, 100, b"hello");
    let mut right = left.clone();
    right.no = 2;
    right.timestamp = 2.0;
    let result = compare(&left, &right);
    assert!(result.field_differences.is_empty());
    assert_eq!(result.first_byte_difference, None);
}
