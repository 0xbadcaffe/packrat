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

#[test]
fn udp_dns_requires_capture_lengths_that_support_the_ip_datagram() {
    let ipv4 = dns_packet(1, true, "192.0.2.53", "192.0.2.8", 5, "sample.test");
    let ipv6 = dns_ipv6_packet(2, true, "2001:db8::53", "2001:db8::8", 5, "sample.test");
    for (reply, field) in [(ipv4, 16), (ipv6, 18)] {
        let actual = reply.bytes.len() as u32;
        let capture = |captured_length, wire_length| CaptureMetadata {
            timestamp: None, captured_length, wire_length, link_type: 1,
            section_id: 0, interface_id: 0, interface_name: None, comments: Vec::new(),
        };
        let length = u16::from_be_bytes(reply.bytes[field..field + 2].try_into().unwrap());
        let mut bigger_ip = reply.clone();
        bigger_ip.bytes[field..field + 2].copy_from_slice(&(length + 8).to_be_bytes());
        for metadata in [None, Some(capture(actual, actual + 7))] {
            let mut impossible = bigger_ip.clone();
            impossible.capture = metadata;
            assert!(DnsTransactionTracker::default().observe(&impossible).is_empty());
        }
        bigger_ip.capture = Some(capture(actual, actual + 8));
        assert_eq!(DnsTransactionTracker::default().observe(&bigger_ip)[0].kind,
            DnsFindingKind::ReplyWithoutObservedQuery);

        for metadata in [capture(actual - 1, actual + 8), capture(actual, actual - 1)] {
            let mut inconsistent = reply.clone();
            inconsistent.capture = Some(metadata);
            assert!(DnsTransactionTracker::default().observe(&inconsistent).is_empty());
        }
        let mut cut_dns = reply.clone();
        cut_dns.bytes.pop();
        cut_dns.capture = Some(capture(actual - 1, actual));
        assert!(DnsTransactionTracker::default().observe(&cut_dns).is_empty());
        assert_eq!(DnsTransactionTracker::default().observe(&reply)[0].kind,
            DnsFindingKind::ReplyWithoutObservedQuery);
    }
}

fn tcp_dns(no: u64, reply: bool, resolver_octet: u8, name: &str) -> Packet {
    let dns = dns_packet(no, reply, "", "", 5, name);
    let message = &dns.bytes[42..];
    let mut wire = vec![0; 54];
    wire[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    wire[14] = 0x45;
    wire[16..18].copy_from_slice(&((42 + message.len()) as u16).to_be_bytes());
    wire[22] = 64;
    wire[23] = 6;
    let client = [10, 0, 0, 8];
    let resolver = [10, 0, 0, resolver_octet];
    let (source, destination, ports) = if reply {
        (resolver, client, [53_u16, 40_000])
    } else {
        (client, resolver, [40_000_u16, 53])
    };
    wire[26..30].copy_from_slice(&source);
    wire[30..34].copy_from_slice(&destination);
    wire[34..36].copy_from_slice(&ports[0].to_be_bytes());
    wire[36..38].copy_from_slice(&ports[1].to_be_bytes());
    wire[46] = 0x50;
    wire[47] = 0x18;
    wire.extend((message.len() as u16).to_be_bytes());
    wire.extend(message);
    packrat_tui::net::parser::parse_ethernet(&wire, no, no as f64)
}

#[test]
fn tcp_dns_exchange_requires_one_complete_message_and_matches_the_resolver() {
    let mut tracker = DnsTransactionTracker::default();
    let udp_query = dns_packet(1, false, "10.0.0.8", "10.0.0.53", 5, "udp.test");
    assert!(tracker.observe(&udp_query).is_empty());
    let tcp_reply = tcp_dns(2, true, 53, "tcp.test");
    assert_eq!(
        tracker.observe(&tcp_reply)[0].kind,
        DnsFindingKind::ReplyWithoutObservedQuery
    );

    let query = tcp_dns(3, false, 53, "tcp.test");
    assert!(tracker.observe(&query).is_empty());
    let different_peer = tcp_dns(4, true, 54, "tcp.test");
    assert_eq!(
        tracker.observe(&different_peer)[0].kind,
        DnsFindingKind::ReplyWithoutObservedQuery
    );
    let mut partial = tcp_dns(5, true, 53, "tcp.test");
    partial.bytes.pop();
    let mut extra = tcp_dns(6, true, 53, "tcp.test");
    extra.bytes.extend([0, 12]);
    let ip_length = (extra.bytes.len() - 14) as u16;
    extra.bytes[16..18].copy_from_slice(&ip_length.to_be_bytes());
    for packet in [partial, extra] {
        assert!(tracker.observe(&packet).is_empty());
        assert!(tracker.exchange_for_packet(&packet).is_none());
    }

    let reply = tcp_dns(7, true, 53, "tcp.test");
    assert!(tracker.observe(&reply).is_empty());
    let exchange = tracker.exchange_for_packet(&reply).unwrap();
    assert_eq!(exchange.transport, "TCP");
    assert_eq!(exchange.query_packet, 3);
    assert_eq!(exchange.replies[0].packet, 7);
    assert!(
        tracker
            .exchange_for_packet(&udp_query)
            .unwrap()
            .replies
            .is_empty()
    );
}

fn tcp_dns_slice(template: &Packet, no: u64, sequence: u32, flags: u8, payload: &[u8]) -> Packet {
    let mut wire = template.bytes[..54].to_vec();
    wire[16..18].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    wire[38..42].copy_from_slice(&sequence.to_be_bytes());
    wire[47] = flags;
    wire.extend(payload);
    packrat_tui::net::parser::parse_ethernet(&wire, no, no as f64)
}

#[test]
fn reconstructed_tcp_dns_exchanges_retain_frames_and_separate_coalesced_messages() {
    let query = tcp_dns(1, false, 53, "first.test");
    let mut query2 = tcp_dns(1, false, 53, "second.test");
    query2.bytes[56..58].copy_from_slice(&6_u16.to_be_bytes());
    let reply = tcp_dns(1, true, 53, "different.test");
    let mut reply2 = tcp_dns(1, true, 53, "second.test");
    reply2.bytes[56..58].copy_from_slice(&6_u16.to_be_bytes());

    let mut core = AnalysisCore::default();
    core.analyze(&tcp_dns_slice(&query, 1, 100, 0x02, &[]));
    core.analyze(&tcp_dns_slice(&reply, 2, 500, 0x12, &[]));
    let first = tcp_dns_slice(&query, 3, 101, 0x18, &query.bytes[54..59]);
    core.analyze(&first);
    let mut rest = query.bytes[59..].to_vec();
    rest.extend_from_slice(&query2.bytes[54..]);
    let shared = tcp_dns_slice(&query, 4, 106, 0x18, &rest);
    core.analyze(&shared);

    let mut responses = reply.bytes[54..].to_vec();
    responses.extend_from_slice(&reply2.bytes[54..]);
    core.analyze(&tcp_dns_slice(&reply, 5, 505, 0x18, &responses[4..]));
    assert!(
        core.alert_center
            .items
            .iter()
            .all(|alert| alert.title != "DNS transaction question mismatch")
    );
    core.analyze(&tcp_dns_slice(&reply, 6, 501, 0x18, &responses[..4]));
    let alert = core
        .alert_center
        .items
        .iter()
        .find(|alert| alert.title == "DNS transaction question mismatch")
        .unwrap();
    assert_eq!(alert.packet_no, 6);
    assert_eq!(alert.packet_refs, [4, 3, 5, 6]);
    let exchange = core.security.dns_exchange_for_packet(&first).unwrap();
    assert_eq!(exchange.question, "first.test");
    assert_eq!(exchange.query_frames, [3, 4]);
    assert_eq!(exchange.replies[0].frames, [5, 6]);
    assert!(core.security.dns_exchange_for_packet(&shared).is_none());
    assert!(
        core.alert_center
            .items
            .iter()
            .all(|alert| alert.title != "DNS reply without observed query")
    );
}

#[test]
fn reconstructed_dns_does_not_use_conflicting_stream_bytes() {
    let reply = tcp_dns(1, true, 53, "sample.test");
    let bytes = &reply.bytes[54..];
    let mut core = AnalysisCore::default();
    core.analyze(&tcp_dns_slice(&reply, 1, 500, 0x12, &[]));
    core.analyze(&tcp_dns_slice(&reply, 2, 501, 0x18, &bytes[..8]));
    let mut overlap = bytes[4..8].to_vec();
    overlap[0] ^= 1;
    core.analyze(&tcp_dns_slice(&reply, 3, 505, 0x18, &overlap));
    core.analyze(&tcp_dns_slice(&reply, 4, 509, 0x18, &bytes[8..]));
    assert!(
        core.alert_center
            .items
            .iter()
            .all(|alert| alert.title != "DNS reply without observed query")
    );
}
