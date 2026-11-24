use super::*;

const LOCAL: &str = "10.0.0.5";
const RESOLVER: &str = "10.0.0.53";
type Clock = (u32, u32);
const PRIMARY: Clock = (0, 0);

fn clock(mut packet: Packet, (section_id, interface_id): Clock, seconds: u64) -> Packet {
    packet.timestamp = seconds as f64;
    let length = packet.bytes.len() as u32;
    packet.capture = Some(CaptureMetadata {
        timestamp: Some(CaptureTimestamp {
            ticks: seconds, resolution: TimestampResolution::Decimal(0), offset_seconds: 0,
        }),
        captured_length: length,
        wire_length: length,
        link_type: 1,
        section_id,
        interface_id,
        interface_name: None,
        comments: Vec::new(),
    });
    packet
}

fn exchange(
    tracker: &mut DnsTransactionTracker, frame: &mut u64, [client, resolver]: [&str; 2],
    (path, seconds): (Clock, u64), id: u16, name: &str, nxdomain: bool,
) -> Vec<DnsFindingKind> {
    let query = clock(dns_packet(*frame, false, client, resolver, id, name), path, seconds);
    let mut reply = clock(dns_packet(*frame + 1, true, resolver, client, id, name), path, seconds + 1);
    if nxdomain { reply.bytes[45] = 0x83; }
    *frame += 2;
    tracker.observe(&query);
    tracker.observe(&reply).into_iter().map(|finding| finding.kind).collect()
}

#[test]
fn full_dns_transaction_table_does_not_expire_queries_from_another_clock() {
    for marker_path in [PRIMARY, (0, 1), (1, 0)] {
        let mut tracker = DnsTransactionTracker::default();
        for id in 1..=2048 {
            let query = dns_packet(u64::from(id), false, LOCAL, RESOLVER, id, "example.test");
            tracker.observe(&clock(query, PRIMARY, 10));
        }
        let marker = clock(dns_packet(2049, false, LOCAL, RESOLVER, 2049, "example.test"), marker_path, 100);
        tracker.observe(&marker);
        let admit = marker_path == PRIMARY;
        assert_eq!(tracker.exchange_for_packet(&marker).is_some(), admit, "marker on {marker_path:?}");
        let reply = clock(dns_packet(2050, true, RESOLVER, LOCAL, 1, "example.test"), PRIMARY, 11);
        let findings = tracker.observe(&reply);
        assert_eq!(tracker.exchange_for_packet(&reply).is_some(), !admit);
        assert_eq!(findings.iter().any(|finding| finding.kind == DnsFindingKind::ReplyWithoutObservedQuery), admit);
    }
}

#[test]
fn full_nxdomain_tracker_keeps_distinct_names_from_another_clock() {
    for marker_path in [PRIMARY, (0, 1), (1, 0)] {
        let mut tracker = DnsTransactionTracker::default();
        let mut frame = 1;
        for id in 1..20 {
            assert!(!exchange(&mut tracker, &mut frame, [LOCAL, RESOLVER], (PRIMARY, 10),
                id, &format!("miss{id}.test"), true).contains(&DnsFindingKind::NxDomainBurst));
        }
        for i in 0..511 {
            exchange(&mut tracker, &mut frame, [&format!("10.20.{}.{}", i / 256, i % 256), RESOLVER],
                (PRIMARY, 10), 1, "missing.test", true);
        }
        exchange(&mut tracker, &mut frame, [LOCAL, RESOLVER], (marker_path, 100), 20, "marker.test", true);
        let final_reply = exchange(&mut tracker, &mut frame, [LOCAL, RESOLVER], (PRIMARY, 20), 21, "last.test", true);
        assert_eq!(final_reply.contains(&DnsFindingKind::NxDomainBurst), marker_path != PRIMARY);
    }
}

#[test]
fn full_external_resolver_tracker_does_not_reset_another_clocks_repeat_suppression() {
    let resolver = "8.8.8.8";
    for marker_path in [PRIMARY, (0, 1), (1, 0)] {
        let mut tracker = DnsTransactionTracker::default();
        let mut frame = 1;
        assert_eq!(exchange(&mut tracker, &mut frame, [LOCAL, resolver], (PRIMARY, 10),
            1, "example.test", false), [DnsFindingKind::ExternalResolver]);
        for i in 0..511 {
            exchange(&mut tracker, &mut frame, [&format!("10.20.{}.{}", i / 256, i % 256), resolver],
                (PRIMARY, 10), 1, "example.test", false);
        }
        let marker = exchange(&mut tracker, &mut frame, ["10.0.0.8", resolver], (marker_path, 4000),
            2, "marker.test", false);
        assert_eq!(marker.contains(&DnsFindingKind::ExternalResolver), marker_path == PRIMARY);
        let repeat = exchange(&mut tracker, &mut frame, [LOCAL, resolver], (PRIMARY, 20), 3, "example.test", false);
        assert_eq!(repeat.contains(&DnsFindingKind::ExternalResolver), marker_path == PRIMARY);
    }
}
