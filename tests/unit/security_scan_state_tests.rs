use super::*;
use crate::net::parser::parse_ethernet;

#[test]
fn unique_probe_and_latch_state_are_bounded_within_one_scan_window() {
    let mut engine = SecurityEngine::default();
    let mut packet = parse_ethernet(&[], 1, 1.0);
    packet.src = "192.0.2.1".into();
    for host in 1..=100 {
        packet.dst = format!("198.51.100.{host}");
        for port in 1..=SCAN_UNIQUE_THRESHOLD as u16 {
            engine.record_scan_probe(&packet, port, "TCP");
            packet.no += 1;
            packet.timestamp += 0.001;
        }
    }
    let state = engine.scan_sources.get(&scan_key(&packet, "TCP")).unwrap();
    assert_eq!(state.probes.len(), MAX_SCAN_PROBES_PER_SOURCE);
    assert!(state.vertical_alerted.len() <= state.probes.len());
    assert!(state.horizontal_alerted.len() <= state.probes.len());
    assert!(state.vertical_alerted.contains("198.51.100.100"));
    assert!(!state.vertical_alerted.contains("198.51.100.1"));
}

#[test]
fn scan_rules_rearm_after_most_evidence_expires_without_realerting_on_sustained_traffic() {
    for (signature, vertical, echo) in [
        ("Horizontal host scan", false, false),
        ("Vertical port scan", true, false),
        ("ICMP address sweep", false, true),
    ] {
        let mut engine = SecurityEngine::default();
        let mut packet = parse_ethernet(&[], 1, 1.0);
        packet.src = "192.0.2.1".into();
        let mut observe = |engine: &mut SecurityEngine, time: f64, targets: std::ops::RangeInclusive<u16>| {
            for target in targets {
                packet.timestamp = time;
                packet.dst = format!("198.51.100.{}", if vertical { 1 } else { target });
                if echo {
                    engine.record_echo_request(&packet, "ICMP");
                } else {
                    engine.record_scan_probe(&packet, if vertical { target } else { 443 }, "TCP");
                }
                packet.no += 1;
            }
            engine.ids_alerts.iter().filter(|alert| alert.signature == signature).count()
        };

        assert_eq!(observe(&mut engine, 1.0, 1..=12), 1);
        assert_eq!(observe(&mut engine, 12.0, 1..=6), 1);
        // Six probes remain active, so reaching the threshold again is not a new burst.
        assert_eq!(observe(&mut engine, 17.0, 13..=18), 1);
        assert_eq!(observe(&mut engine, 25.0, 18..=18), 1);
        // One lingering probe must not suppress a new burst of eleven probes.
        assert_eq!(observe(&mut engine, 33.0, 19..=29), 2);
        let latest = engine.findings.ids.last().unwrap();
        assert_eq!(latest.alert.pkt_no, 36);
        assert_eq!(latest.related_packets, (25..=35).collect::<Vec<_>>());
    }
}

#[test]
fn syn_rule_records_renewed_spikes_but_not_sustained_or_retransmitted_syns() {
    let mut engine = SecurityEngine::default();
    let mut packet = parse_ethernet(&[], 1, 1.0);
    packet.src = "192.0.2.1".into();
    packet.dst = "198.51.100.1".into();
    let mut observe = |engine: &mut SecurityEngine, time: f64, count: usize, sequence: Option<u32>| {
        for _ in 0..count {
            packet.timestamp = time;
            engine.record_syn_arrival(&packet, 443, 40_000, sequence.unwrap_or(packet.no as u32));
            packet.no += 1;
        }
        engine.ids_alerts.len()
    };
    assert_eq!(observe(&mut engine, 1.0, 50, None), 0);
    assert_eq!(observe(&mut engine, 1.5, 50, None), 1);
    assert_eq!(observe(&mut engine, 2.25, 50, None), 1);
    assert_eq!(observe(&mut engine, 3.0, 1, None), 1);
    assert_eq!(observe(&mut engine, 3.5, 120, Some(151)), 1);
    assert_eq!(observe(&mut engine, 3.5, 99, None), 2);
    let renewed = engine.findings.ids.last().unwrap();
    assert_eq!(renewed.alert.pkt_no, 370);
    assert_eq!(renewed.related_packets, std::iter::once(151).chain(272..370).collect::<Vec<_>>());
}
