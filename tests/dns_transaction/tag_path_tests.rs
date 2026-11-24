use super::*;
use packrat_tui::net::parser::parse_ethernet;

fn tagged(frame: u64, response: bool, tpid: u16, tci: u16) -> Packet {
    let client = "10.0.0.5";
    let resolver = "10.0.0.53";
    let (source, destination) = if response { (resolver, client) } else { (client, resolver) };
    let mut raw = dns_packet(frame, response, source, destination, 69, "example.test").bytes;
    raw.splice(12..12, [tpid, tci].into_iter().flat_map(u16::to_be_bytes));
    parse_ethernet(&raw, frame, frame as f64)
}

#[test]
fn dns_correlation_and_investigation_require_the_observed_tag_path() {
    let mut tracker = DnsTransactionTracker::default();
    let query = tagged(1, false, 0x8100, 20);
    let other_reply = tagged(2, true, 0x88a8, 20);
    assert!(tracker.observe(&query).is_empty());
    let finding = tracker.observe(&other_reply);
    assert_eq!(finding.len(), 1);
    assert_eq!(finding[0].kind, DnsFindingKind::ReplyWithoutObservedQuery);
    assert!(finding[0].related_packets.is_empty());
    assert!(tracker.exchange_for_packet(&other_reply).is_none());

    let other_query = tagged(3, false, 0x88a8, 20);
    let same_reply = tagged(4, true, 0x8100, 0xb014);
    let other_matched_reply = tagged(5, true, 0x88a8, 0xb014);
    for pkt in [&other_query, &same_reply, &other_matched_reply] {
        assert!(tracker.observe(pkt).is_empty(), "frame {}", pkt.no);
    }
    for (pkt, reply) in [(&query, 4), (&other_query, 5)] {
        let exchange = tracker.exchange_for_packet(pkt).unwrap();
        assert_eq!(exchange.replies.iter().map(|entry| entry.packet).collect::<Vec<_>>(), [reply]);
    }
}
