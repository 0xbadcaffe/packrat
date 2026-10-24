use super::*;

fn dns_packet(no: u64, timestamp: f64, response: bool) -> Packet {
    let mut bytes = vec![0_u8; 14 + 20 + 8 + 12];
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[23] = 17;
    bytes[42..44].copy_from_slice(&0x1234_u16.to_be_bytes());
    if response { bytes[44] = 0x80; }
    Packet { capture: None,
        no,
        timestamp,
        src: if response { "8.8.8.8" } else { "10.0.0.5" }.into(),
        dst: if response { "10.0.0.5" } else { "8.8.8.8" }.into(),
        protocol: "DNS".into(),
        length: bytes.len() as u16,
        info: String::new(),
        src_port: Some(if response { 53 } else { 50000 }),
        dst_port: Some(if response { 50000 } else { 53 }),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes,
    }
}

#[test]
fn measures_dns_request_response_latency() {
    let mut pulse = WirePulse::default();
    pulse.observe(&dns_packet(1, 1.0, false));
    pulse.observe(&dns_packet(2, 1.025, true));
    assert_eq!(pulse.samples.len(), 1);
    assert!((pulse.samples[0].latency_ms - 25.0).abs() < 0.001);
}
