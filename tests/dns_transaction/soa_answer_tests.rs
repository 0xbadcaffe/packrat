use super::{append_answer, dns_packet};
use packrat_tui::analysis::dns_transactions::{DnsFindingKind, DnsTransactionTracker};
use packrat_tui::net::packet::Packet;

fn soa_packet(no: u64, reply: bool) -> Packet {
    let (client, resolver) = ("192.0.2.5", "192.0.2.53");
    let (source, destination) = if reply {
        (resolver, client)
    } else {
        (client, resolver)
    };
    let mut packet = dns_packet(no, reply, source, destination, 47, "zone.test");
    let question_type = packet.bytes.len() - 4;
    packet.bytes[question_type..question_type + 2].copy_from_slice(&6_u16.to_be_bytes());
    packet
}

fn rdata(compressed: bool, serial: u32) -> Vec<u8> {
    let mut data = if compressed {
        b"\x02ns\xc0\x0c\x05admin\xc0\x0c".to_vec()
    } else {
        b"\x02NS\x04ZONE\x04TEST\0\x05ADMIN\x04ZONE\x04TEST\0".to_vec()
    };
    for value in [serial, 3_600, 600, 86_400, 60] {
        data.extend(value.to_be_bytes());
    }
    data
}

#[test]
fn soa_compares_serial_and_ignores_case_compression_and_ttl() {
    let mut tracker = DnsTransactionTracker::default();
    let query = soa_packet(1, false);
    let mut first = soa_packet(2, true);
    let mut equivalent = soa_packet(3, true);
    let mut changed = soa_packet(4, true);
    append_answer(&mut first, b"\xc0\x0c", 6, 300, &rdata(true, 5));
    append_answer(&mut equivalent, b"\xc0\x0c", 6, 299, &rdata(false, 5));
    append_answer(&mut changed, b"\xc0\x0c", 6, 299, &rdata(false, 6));
    for packet in [query, first, equivalent] {
        assert!(tracker.observe(&packet).is_empty());
    }
    let findings = tracker.observe(&changed);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, DnsFindingKind::ChangedAnswerSet);
    assert_eq!(findings[0].related_packets, [1, 2]);
}

#[test]
fn invalid_soa_field_boundaries_do_not_claim_semantic_changes() {
    let mut tracker = DnsTransactionTracker::default();
    let mut first = soa_packet(2, true);
    append_answer(&mut first, b"\xc0\x0c", 6, 300, &rdata(true, 5));
    assert!(tracker.observe(&soa_packet(1, false)).is_empty());
    assert!(tracker.observe(&first).is_empty());

    let mut truncated = rdata(false, 6);
    truncated.pop();
    let mut trailing = rdata(false, 6);
    trailing.push(0);
    for (frame, data) in [truncated, trailing].iter().enumerate() {
        let mut reply = soa_packet(frame as u64 + 3, true);
        append_answer(&mut reply, b"\xc0\x0c", 6, 299, data);
        let findings = tracker.observe(&reply);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, DnsFindingKind::ChangedReply);
    }
}
