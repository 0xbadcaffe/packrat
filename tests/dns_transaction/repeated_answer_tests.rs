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
