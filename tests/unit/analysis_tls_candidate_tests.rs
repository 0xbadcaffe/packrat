use super::*;

fn packet(protocol: &str, bytes: Vec<u8>) -> Packet {
    Packet { capture: None,
        no: 1,
        timestamp: 1.0,
        src: "192.0.2.1".into(),
        dst: "198.51.100.2".into(),
        protocol: protocol.into(),
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
fn tls_candidate_gate_keeps_named_and_raw_record_traffic() {
    assert!(is_tls_candidate(&packet("TLS", vec![0; 64])));
    assert!(is_tls_candidate(&packet("TCP", vec![0, 0x16, 0x03, 0x03, 0])));
    assert!(!is_tls_candidate(&packet("HTTP", b"GET / HTTP/1.1".to_vec())));
}
