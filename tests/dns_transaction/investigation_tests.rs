use super::*;

#[test]
fn dns_investigation_links_query_normal_reply_and_competing_reply() {
    let mut tracker = DnsTransactionTracker::default();
    let query = dns_packet(1, false, "10.0.0.5", "10.0.0.53", 35, "example.test");
    let reply = dns_packet(2, true, "10.0.0.53", "10.0.0.5", 35, "example.test");
    let conflict = dns_packet(3, true, "10.0.0.54", "10.0.0.5", 35, "example.test");
    tracker.observe(&query);
    let pending = tracker.exchange_for_packet(&query).unwrap();
    assert!(pending.replies.is_empty());
    tracker.observe(&reply);
    tracker.observe(&conflict);
    for frame in [&query, &reply, &conflict] {
        let evidence = tracker.exchange_for_packet(frame).unwrap();
        assert_eq!(evidence.query_packet, 1);
        assert_eq!(evidence.transaction_id, 35);
        assert_eq!(evidence.expected_resolver, "10.0.0.53");
        assert_eq!(evidence.question, "example.test");
        assert_eq!(evidence.replies.iter().map(|reply| reply.packet).collect::<Vec<_>>(), [2, 3]);
        assert_eq!(evidence.replies[1].resolver, "10.0.0.54");
    }
    let mut unrelated = conflict.clone();
    unrelated.no = 25;
    assert!(tracker.exchange_for_packet(&unrelated).is_none());
    unrelated.no = 3;
    unrelated.vlan_id = Some(10);
    assert!(tracker.exchange_for_packet(&unrelated).is_none());

    let reused = dns_packet(4, false, "10.0.0.5", "10.0.0.53", 35, "example.test");
    tracker.observe(&reused);
    assert!(tracker.exchange_for_packet(&query).is_none());
    assert!(tracker.exchange_for_packet(&conflict).is_none());
    assert_eq!(tracker.exchange_for_packet(&reused).unwrap().query_packet, 4);
}

#[test]
fn dns_investigation_bounds_alternate_replies() {
    let mut tracker = DnsTransactionTracker::default();
    let query = dns_packet(1, false, "10.0.0.5", "10.0.0.53", 35, "example.test");
    tracker.observe(&query);
    for no in 2..=12 {
        let mut reply = dns_packet(no, true, &format!("10.0.0.{}", 51 + no), "10.0.0.5", 35, "example.test");
        reply.timestamp = no as f64 / 100.0 + 1.0;
        tracker.observe(&reply);
    }
    let evidence = tracker.exchange_for_packet(&query).unwrap();
    assert_eq!(evidence.replies.len(), 9);
    assert!(evidence.additional_replies_omitted);
}

#[test]
fn exact_copies_of_retained_alternate_dns_replies_do_not_increment_alert_hits() {
    let resolver = "10.0.0.53";
    let client = "10.0.0.5";
    for (source, rule) in [
        (resolver, "dns.changed_answers"),
        ("10.0.0.54", "dns.competing_responders"),
    ] {
        let mut core = AnalysisCore::default();
        let query = dns_packet(1, false, client, resolver, 47, "example.test");
        let reply = dns_packet(2, true, resolver, client, 47, "example.test");
        let mut alternate = dns_packet(3, true, source, client, 47, "example.test");
        alternate.bytes[45] = 0x83;
        let mut copy = alternate.clone();
        copy.no = 4;
        copy.timestamp = 3.1;
        let mut distinct = copy.clone();
        distinct.no = 5;
        distinct.timestamp = 3.2;
        distinct.bytes[45] = 0x82;
        for packet in [&query, &reply, &alternate, &copy, &distinct] {
            core.analyze(packet);
        }
        let finding = core.alert_center.items.iter().find(|alert| {
            alert.provenance.as_ref().is_some_and(|provenance| provenance.rule_id == rule)
        }).unwrap();
        assert_eq!(finding.hit_count, 2, "{rule}");
        assert_eq!(finding.packet_refs, [1, 2, 3, 5], "{rule}");
        let exchange = core.security.dns_exchange_for_packet(&query).unwrap();
        assert_eq!(exchange.replies.iter().map(|reply| reply.packet).collect::<Vec<_>>(), [2, 3, 5]);
    }
}
