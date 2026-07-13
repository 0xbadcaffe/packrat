use packrat_tui::analysis::packet_fields::{extract_fields, filter_fields};
use packrat_tui::net::packet::Packet;

fn field<'a>(fields: &'a [packrat_tui::analysis::packet_fields::PacketField], path: &str) -> &'a str {
    fields.iter().find(|field| field.path == path).map(|field| field.value.as_str()).unwrap_or("")
}

fn packet(bytes: Vec<u8>, proto: &str) -> Packet {
    Packet {
        no: 42,
        timestamp: 1.25,
        src: "192.0.2.10".into(),
        dst: "198.51.100.7".into(),
        protocol: proto.into(),
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

fn ethernet_ipv4_tcp(seq: u32, ack: u32) -> Vec<u8> {
    let mut bytes = ethernet_header(0x0800);
    bytes.extend(ipv4_header(6, 40));
    bytes.extend(50_000u16.to_be_bytes());
    bytes.extend(443u16.to_be_bytes());
    bytes.extend(seq.to_be_bytes());
    bytes.extend(ack.to_be_bytes());
    bytes.extend([0x50, 0x18]);
    bytes.extend(4096u16.to_be_bytes());
    bytes.extend([0, 0, 0, 0]);
    bytes
}

fn ethernet_vlan_ipv4_udp() -> Vec<u8> {
    let mut bytes = vec![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x81, 0x00,
    ];
    let tci = (5u16 << 13) | (1u16 << 12) | 123u16;
    bytes.extend(tci.to_be_bytes());
    bytes.extend(0x0800u16.to_be_bytes());
    bytes.extend(ipv4_header(17, 28));
    bytes.extend(53u16.to_be_bytes());
    bytes.extend(5353u16.to_be_bytes());
    bytes.extend(8u16.to_be_bytes());
    bytes.extend(0u16.to_be_bytes());
    bytes
}

fn ethernet_ipv4_udp_dtls() -> Vec<u8> {
    let dtls = [
        0x16, 0xfe, 0xfd,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
        0x00, 0x10,
    ];
    let mut bytes = ethernet_header(0x0800);
    bytes.extend(ipv4_header(17, 20 + 8 + dtls.len() as u16));
    bytes.extend(5684u16.to_be_bytes());
    bytes.extend(5684u16.to_be_bytes());
    bytes.extend((8 + dtls.len() as u16).to_be_bytes());
    bytes.extend(0u16.to_be_bytes());
    bytes.extend(dtls);
    bytes
}

fn ethernet_header(ether_type: u16) -> Vec<u8> {
    let mut bytes = vec![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    ];
    bytes.extend(ether_type.to_be_bytes());
    bytes
}

fn ipv4_header(proto: u8, total_len: u16) -> Vec<u8> {
    let mut bytes = vec![
        0x45, 0x00,
        0x00, 0x00,
        0x12, 0x34,
        0x00, 0x00,
        64, proto,
        0x00, 0x00,
        192, 0, 2, 10,
        198, 51, 100, 7,
    ];
    bytes[2..4].copy_from_slice(&total_len.to_be_bytes());
    bytes
}

#[test]
fn extracts_tcp_sequence_and_ack_numbers() {
    let pkt = packet(ethernet_ipv4_tcp(0x0102_0304, 0x0506_0708), "TCP");
    let fields = extract_fields(&pkt);

    assert_eq!(field(&fields, "tcp.seq"), "16909060");
    assert_eq!(field(&fields, "tcp.ack"), "84281096");
    assert_eq!(field(&fields, "tcp.dstport"), "443");
}

#[test]
fn extracts_vlan_tci_fields() {
    let pkt = packet(ethernet_vlan_ipv4_udp(), "UDP");
    let fields = extract_fields(&pkt);

    assert_eq!(field(&fields, "vlan.id"), "123");
    assert_eq!(field(&fields, "vlan.pcp"), "5");
    assert_eq!(field(&fields, "vlan.dei"), "1");
}

#[test]
fn extracts_dtls_record_fields() {
    let pkt = packet(ethernet_ipv4_udp_dtls(), "DTLS");
    let fields = extract_fields(&pkt);

    assert_eq!(field(&fields, "dtls.record.content_type"), "handshake");
    assert_eq!(field(&fields, "dtls.record.epoch"), "1");
    assert_eq!(field(&fields, "dtls.record.sequence_number"), "7");
    assert_eq!(field(&fields, "dtls.record.length"), "16");
}

#[test]
fn filters_fields_by_keyboard_search_text() {
    let pkt = packet(ethernet_ipv4_tcp(7, 8), "TCP");
    let fields = extract_fields(&pkt);
    let visible = filter_fields(&fields, "sequence");

    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].path, "tcp.seq");
}
