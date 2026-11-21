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
