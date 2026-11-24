use super::{DnsFindingKind, DnsTransactionTracker, append_answer, dns_packet};

#[test]
fn repeated_changed_dns_answers_do_not_open_another_finding() {
    let client = "192.0.2.10";
    let resolver = "192.0.2.53";
    let mut tracker = DnsTransactionTracker::default();
    let query = dns_packet(1, false, client, resolver, 86, "safe.example");
    let reply = |no, owner: &[u8], ttl, last_octet| {
        let mut packet = dns_packet(no, true, resolver, client, 86, "safe.example");
        append_answer(&mut packet, owner, 1, ttl, &[198, 51, 100, last_octet]);
        packet
    };
    let compressed = [0xc0, 0x0c];
    assert!(tracker.observe(&query).is_empty());
    assert!(tracker.observe(&reply(2, &compressed, 300, 1)).is_empty());
    let first_change = tracker.observe(&reply(3, &compressed, 300, 2));
    assert_eq!(first_change[0].kind, DnsFindingKind::ChangedAnswerSet);
    assert_eq!(first_change[0].related_packets, [1, 2]);

    let expanded = b"\x04SAFE\x07EXAMPLE\0";
    assert!(tracker.observe(&reply(4, expanded, 299, 2)).is_empty());
    let next_change = tracker.observe(&reply(5, expanded, 298, 3));
    assert_eq!(next_change[0].kind, DnsFindingKind::ChangedAnswerSet);
    assert_eq!(next_change[0].related_packets, [1, 2]);
}

#[test]
fn changed_dns_response_codes_follow_capture_order_after_baseline_promotion() {
    let client = "192.0.2.10";
    let resolver = "192.0.2.53";
    for (timestamp, expected) in [(2.5, "0 to 3"), (3.0, "3 to 0"), (4.0, "3 to 0")] {
        let mut tracker = DnsTransactionTracker::default();
        let query = dns_packet(1, false, client, resolver, 86, "safe.example");
        let competing = dns_packet(2, true, "192.0.2.54", client, 86, "safe.example");
        let mut expected_reply = dns_packet(3, true, resolver, client, 86, "safe.example");
        expected_reply.bytes[45] = 0x83;
        assert!(tracker.observe(&query).is_empty());
        tracker.observe(&competing);
        let conflict = tracker.observe(&expected_reply);
        assert_eq!(conflict[0].kind, DnsFindingKind::ConflictingResponse);
        assert_eq!(conflict[0].related_packets, [1, 2]);
        let mut reply = dns_packet(4, true, resolver, client, 86, "safe.example");
        reply.timestamp = timestamp;
        let change = tracker.observe(&reply);
        assert_eq!(change[0].kind, DnsFindingKind::ChangedAnswerSet);
        assert_eq!(change[0].related_packets, [1, 3]);
        assert!(change[0].detail.contains(&format!("response code ({expected}) in capture order")));
    }
}

#[test]
fn late_dns_reply_uses_the_latest_retained_retry_that_precedes_it() {
    let (client, resolver) = ("192.0.2.10", "192.0.2.53");
    let query = dns_packet(1, false, client, resolver, 87, "safe.example");
    let mut tracker = DnsTransactionTracker::default();
    tracker.observe(&query);
    for (no, timestamp) in [(2, 22.0), (3, 29.0), (4, 43.0)] {
        let mut retry = dns_packet(no, false, client, resolver, 87, "safe.example");
        retry.timestamp = timestamp;
        tracker.observe(&retry);
    }
    let mut reply = dns_packet(5, true, resolver, client, 87, "safe.example");
    reply.timestamp = 34.0;
    assert!(tracker.observe(&reply).is_empty());
    let exchange = tracker.exchange_for_packet(&query).unwrap();
    assert_eq!(exchange.timing_retry.unwrap().packet, 3);
    let mut second = dns_packet(6, true, "192.0.2.54", client, 87, "safe.example");
    second.timestamp = 35.0;
    let conflict = tracker.observe(&second);
    assert_eq!(conflict[0].kind, DnsFindingKind::ConflictingResponse);
    assert_eq!(conflict[0].related_packets, [1, 5, 3]);
}

#[test]
fn dns_reply_without_a_retained_preceding_retry_does_not_bind_to_a_future_retry() {
    let (client, resolver) = ("192.0.2.10", "192.0.2.53");
    let mut tracker = DnsTransactionTracker::default();
    tracker.observe(&dns_packet(1, false, client, resolver, 88, "safe.example"));
    for (no, timestamp) in (2..=10).zip([29.0, 38.0, 39.0, 40.0, 41.0, 42.0, 43.0, 44.0, 45.0]) {
        let mut retry = dns_packet(no, false, client, resolver, 88, "safe.example");
        retry.timestamp = timestamp;
        tracker.observe(&retry);
    }
    let mut reply = dns_packet(11, true, resolver, client, 88, "safe.example");
    reply.timestamp = 34.0;
    let findings = tracker.observe(&reply);
    assert_eq!(findings[0].kind, DnsFindingKind::ReplyWithoutObservedQuery);
    assert!(findings[0].related_packets.is_empty());
}

#[test]
fn replies_delivered_out_of_order_still_match_within_the_reply_window() {
    let (client, resolver, other) = ("192.0.2.10", "192.0.2.53", "192.0.2.54");
    for (timestamp, responder, kind) in [
        (8.0, resolver, None),
        (8.0, other, Some(DnsFindingKind::ConflictingResponse)),
        (6.0, other, Some(DnsFindingKind::ConflictingResponse)),
        (5.0, other, Some(DnsFindingKind::ReplyWithoutObservedQuery)),
    ] {
        let mut tracker = DnsTransactionTracker::default();
        tracker.observe(&dns_packet(1, false, client, resolver, 89, "safe.example"));
        let mut first_processed = dns_packet(2, true, resolver, client, 89, "safe.example");
        first_processed.timestamp = 11.0;
        assert!(tracker.observe(&first_processed).is_empty());
        let mut delayed = dns_packet(3, true, responder, client, 89, "safe.example");
        delayed.timestamp = timestamp;
        let findings = tracker.observe(&delayed);
        assert_eq!(findings.iter().map(|finding| finding.kind).collect::<Vec<_>>(), kind.into_iter().collect::<Vec<_>>());
        if kind == Some(DnsFindingKind::ConflictingResponse) {
            assert_eq!(findings[0].related_packets, [1, 2]);
        }
    }
}

#[test]
fn a_correlated_reply_does_not_make_its_query_retry_valid_for_an_earlier_reply() {
    let (client, resolver) = ("192.0.2.10", "192.0.2.53");
    let mut tracker = DnsTransactionTracker::default();
    tracker.observe(&dns_packet(1, false, client, resolver, 90, "safe.example"));
    for (no, timestamp) in (2..=10).zip([29.0, 38.0, 39.0, 40.0, 41.0, 42.0, 43.0, 44.0, 45.0]) {
        let mut retry = dns_packet(no, false, client, resolver, 90, "safe.example");
        retry.timestamp = timestamp;
        tracker.observe(&retry);
    }
    let mut first = dns_packet(11, true, resolver, client, 90, "safe.example");
    first.timestamp = 39.0;
    assert!(tracker.observe(&first).is_empty());
    let mut delayed = dns_packet(12, true, "192.0.2.54", client, 90, "safe.example");
    // The only preceding retry has fallen out of the bounded cache.
    delayed.timestamp = 34.0;
    let findings = tracker.observe(&delayed);
    assert_eq!(findings[0].kind, DnsFindingKind::ReplyWithoutObservedQuery);
    assert!(findings[0].related_packets.is_empty());
}

#[test]
fn out_of_order_reply_comparison_cites_each_preceding_retry() {
    let (client, resolver) = ("192.0.2.10", "192.0.2.53");
    let mut tracker = DnsTransactionTracker::default();
    for (no, timestamp) in [(1, 1.0), (2, 29.0), (3, 35.0)] {
        let mut query = dns_packet(no, false, client, resolver, 91, "safe.example");
        query.timestamp = timestamp;
        tracker.observe(&query);
    }
    let mut first = dns_packet(4, true, resolver, client, 91, "safe.example");
    first.timestamp = 37.0;
    assert!(tracker.observe(&first).is_empty());
    let mut delayed = dns_packet(5, true, resolver, client, 91, "safe.example");
    delayed.timestamp = 33.0;
    delayed.bytes[45] = 0x83;
    let findings = tracker.observe(&delayed);
    assert_eq!(findings[0].kind, DnsFindingKind::ChangedAnswerSet);
    assert!(findings[0].detail.contains("response code (3 to 0) in capture order"));
    assert_eq!(findings[0].related_packets, [1, 4, 3, 2]);
}
