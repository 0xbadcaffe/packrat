use super::*;

#[test]
fn dns_transport_requires_consistent_ip_headers_link_type_and_supported_tag_depth() {
    let ipv4 = dns_packet(1, true, "192.0.2.53", "192.0.2.8", 5, "sample.test");
    let ipv6 = dns_ipv6_packet(2, true, "2001:db8::53", "2001:db8::8", 5, "sample.test");
    let mut tracker = DnsTransactionTracker::default();
    let mut wrong_v4 = ipv4.clone();
    wrong_v4.bytes[14] = 0x65;
    let mut wrong_v6 = ipv6.clone();
    wrong_v6.bytes[14] = 0x40;
    let mut unsupported = ipv4.clone();
    unsupported.capture = Some(CaptureMetadata {
        timestamp: None,
        captured_length: unsupported.bytes.len() as u32,
        wire_length: unsupported.bytes.len() as u32,
        link_type: 101,
        section_id: 0,
        interface_id: 0,
        interface_name: None,
        comments: Vec::new(),
    });

    let mut qinq = ipv4.clone();
    qinq.bytes
        .splice(12..12, [0x88, 0xa8, 0, 100, 0x81, 0, 0, 10]);
    let mut three_tags = qinq.clone();
    three_tags.bytes.splice(12..12, [0x88, 0xa8, 0, 200]);

    let mut extended = ipv6.clone();
    extended.bytes[20] = 60;
    extended.bytes.splice(54..54, [17, 0, 0, 0, 0, 0, 0, 0]);
    let length = (extended.bytes.len() - 54) as u16;
    extended.bytes[18..20].copy_from_slice(&length.to_be_bytes());
    let mut short_network = extended.clone();
    short_network.bytes[18..20].copy_from_slice(&7_u16.to_be_bytes());

    for packet in [wrong_v4, wrong_v6, unsupported, three_tags, short_network] {
        assert!(tracker.observe(&packet).is_empty());
    }
    for packet in [qinq, extended] {
        let findings = tracker.observe(&packet);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, DnsFindingKind::ReplyWithoutObservedQuery);
    }
}
