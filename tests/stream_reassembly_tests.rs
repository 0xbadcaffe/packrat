use packrat_tui::analysis::stream::{StreamAssembler, StreamKey, tcp_payload_offset};
use packrat_tui::net::packet::Packet;

fn tcp_packet(no: u64, sequence: u32, flags: u8, payload: &[u8]) -> Packet {
    let mut bytes = vec![0_u8; 14 + 20 + 20];
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    bytes[23] = 6;
    bytes[34..36].copy_from_slice(&40_000_u16.to_be_bytes());
    bytes[36..38].copy_from_slice(&443_u16.to_be_bytes());
    bytes[38..42].copy_from_slice(&sequence.to_be_bytes());
    bytes[46] = 0x50;
    bytes[47] = flags;
    bytes.extend_from_slice(payload);
    Packet {
        no,
        timestamp: no as f64,
        src: "10.0.0.1".into(),
        dst: "10.0.0.2".into(),
        protocol: "TCP".into(),
        length: bytes.len() as u16,
        info: String::new(),
        src_port: Some(40_000),
        dst_port: Some(443),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes,
    }
}

fn stream(assembler: &StreamAssembler) -> &packrat_tui::analysis::stream::ReassembledStream {
    let key = StreamKey::from_packet(&tcp_packet(0, 0, 0, &[])).unwrap();
    assembler.get(&key.id()).unwrap()
}

fn ipv6_tcp_packet(no: u64, sequence: u32, payload: &[u8], hop_by_hop: bool) -> Packet {
    let extension_length = if hop_by_hop { 8 } else { 0 };
    let tcp_offset = 14 + 40 + extension_length;
    let mut bytes = vec![0_u8; tcp_offset + 20];
    bytes[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
    bytes[14] = 0x60;
    bytes[18..20].copy_from_slice(&((extension_length + 20 + payload.len()) as u16).to_be_bytes());
    bytes[20] = if hop_by_hop { 0 } else { 6 };
    if hop_by_hop {
        bytes[54] = 6;
        bytes[55] = 0;
    }
    bytes[tcp_offset..tcp_offset + 2].copy_from_slice(&40_000_u16.to_be_bytes());
    bytes[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&443_u16.to_be_bytes());
    bytes[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&sequence.to_be_bytes());
    bytes[tcp_offset + 12] = 0x50;
    bytes[tcp_offset + 13] = 0x18;
    bytes.extend_from_slice(payload);
    Packet {
        no,
        timestamp: no as f64,
        src: "2001:db8::1".into(),
        dst: "2001:db8::2".into(),
        protocol: "TCP".into(),
        length: bytes.len() as u16,
        info: String::new(),
        src_port: Some(40_000),
        dst_port: Some(443),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes,
    }
}

#[test]
fn buffers_out_of_order_segments_until_the_gap_arrives() {
    let mut assembler = StreamAssembler::default();
    assembler.ingest(&tcp_packet(1, 1_000, 0x02, &[]));
    assembler.ingest(&tcp_packet(2, 1_006, 0x18, b"world"));
    assert!(stream(&assembler).client_data.is_empty());
    assembler.ingest(&tcp_packet(3, 1_001, 0x18, b"hello"));
    assert_eq!(stream(&assembler).client_data, b"helloworld");
}

#[test]
fn trims_retransmissions_and_partial_overlaps() {
    let mut assembler = StreamAssembler::default();
    assembler.ingest(&tcp_packet(1, 100, 0x02, &[]));
    assembler.ingest(&tcp_packet(2, 101, 0x18, b"hello"));
    assembler.ingest(&tcp_packet(3, 101, 0x18, b"hello"));
    assembler.ingest(&tcp_packet(4, 104, 0x18, b"loworld"));
    assert_eq!(stream(&assembler).client_data, b"helloworld");
}

#[test]
fn reassembles_across_tcp_sequence_wraparound() {
    let mut assembler = StreamAssembler::default();
    assembler.ingest(&tcp_packet(1, u32::MAX - 2, 0x02, &[]));
    assembler.ingest(&tcp_packet(2, u32::MAX - 1, 0x18, b"ab"));
    assembler.ingest(&tcp_packet(3, 2, 0x18, b"ef"));
    assembler.ingest(&tcp_packet(4, 0, 0x18, b"cd"));
    assert_eq!(stream(&assembler).client_data, b"abcdef");
}

#[test]
fn delays_out_of_order_fin_until_preceding_payload_is_complete() {
    let mut assembler = StreamAssembler::default();
    assembler.ingest(&tcp_packet(1, 10, 0x02, &[]));
    assembler.ingest(&tcp_packet(2, 13, 0x11, &[]));
    assert!(!stream(&assembler).closed);
    assembler.ingest(&tcp_packet(3, 11, 0x18, b"ab"));
    assert_eq!(stream(&assembler).client_data, b"ab");
    assert!(stream(&assembler).closed);
}

#[test]
fn reassembles_ipv6_tcp_with_and_without_extension_headers() {
    for hop_by_hop in [false, true] {
        let packet = ipv6_tcp_packet(1, 500, b"ipv6 payload", hop_by_hop);
        assert_eq!(&packet.bytes[tcp_payload_offset(&packet)..], b"ipv6 payload");
        let key = StreamKey::from_packet(&packet).unwrap();
        let mut assembler = StreamAssembler::default();
        assembler.ingest(&packet);
        assert_eq!(assembler.get(&key.id()).unwrap().client_data, b"ipv6 payload");
    }
}

#[test]
fn malformed_ip_and_tcp_headers_are_not_reassembled_as_payload() {
    let mut packet = tcp_packet(1, 100, 0x18, b"payload");
    packet.bytes[14] = 0x41;
    let key = StreamKey::from_packet(&packet).unwrap();
    let mut assembler = StreamAssembler::default();
    assembler.ingest(&packet);
    assert!(assembler.get(&key.id()).is_none());

    let mut packet = tcp_packet(2, 100, 0x18, b"payload");
    packet.bytes[46] = 0x10;
    assert_eq!(tcp_payload_offset(&packet), packet.bytes.len());
}
