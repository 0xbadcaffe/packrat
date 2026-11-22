use super::{SecurityEngine, ipv6_control_packet};

#[test]
fn ipv6_extension_alert_counts_only_captured_headers() {
    let source = "fe80::1".parse::<std::net::Ipv6Addr>().unwrap().octets();
    let wire = |no, initial, payload: &[u8]| {
        let mut packet = ipv6_control_packet(no, [2, 0, 0, 0, 0, 1], source, 255, payload);
        packet.bytes[20] = initial;
        packet
    };
    let mut headers = vec![0_u8; 9 * 8];
    for header in headers.chunks_exact_mut(8) {
        header[0] = 60;
    }
    let mut padding = wire(1, 60, &headers);
    padding.bytes[18..20].copy_from_slice(&(65_u16).to_be_bytes());
    let mut truncated = wire(2, 60, &headers);
    truncated.bytes.truncate(54 + 67);
    let mut fragment = vec![60, 0, 0, 8, 0, 0, 0, 1];
    fragment.extend_from_slice(&headers);
    let later_fragment = wire(3, 44, &fragment);
    let complete_prefix = wire(4, 60, &headers);
    fragment[3] = 1;
    let first_fragment = wire(5, 44, &fragment);

    let mut security = SecurityEngine::default();
    for packet in [
        &padding,
        &truncated,
        &later_fragment,
        &complete_prefix,
        &first_fragment,
    ] {
        security.update(packet);
    }
    let evidence: Vec<_> = security
        .ids_alerts
        .iter()
        .filter(|alert| alert.signature == "Excessive IPv6 extension headers")
        .map(|alert| alert.pkt_no)
        .collect();
    assert_eq!(evidence, [4, 5]);
}
