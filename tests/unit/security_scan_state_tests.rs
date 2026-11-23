use super::*;
use crate::net::parser::parse_ethernet;

#[test]
fn scan_retains_only_scoped_reply_evidence_present_when_the_alert_opens() {
    let tcp_frame = |no, target, flags, ack: u32, client_port: u16, vlan| {
        let client = [192, 0, 2, 1];
        let host = [198, 51, 100, target];
        let (src, dst, sport, dport) = if flags == 0x02 {
            (client, host, client_port, 443_u16)
        } else {
            (host, client, 443_u16, client_port)
        };
        let mut raw = [0_u8; 54];
        raw[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        raw[14] = 0x45;
        raw[16..18].copy_from_slice(&40_u16.to_be_bytes());
        raw[22] = 64;
        raw[23] = 6;
        raw[26..30].copy_from_slice(&src);
        raw[30..34].copy_from_slice(&dst);
        raw[34..36].copy_from_slice(&sport.to_be_bytes());
        raw[36..38].copy_from_slice(&dport.to_be_bytes());
        raw[38..42].copy_from_slice(&u32::MAX.to_be_bytes());
        raw[42..46].copy_from_slice(&ack.to_be_bytes());
        raw[46] = 0x50;
        raw[47] = flags;
        let mut packet = parse_ethernet(&raw, no, 1.0);
        packet.vlan_id = Some(vlan);
        packet
    };
    let mut engine = SecurityEngine::default();
    for (no, host, flags, ack, port, vlan) in [
        (2, 1, 0x02, 0, 40_000, 10),
        (1, 1, 0x12, 0, 40_000, 10), // Same timestamp, before the SYN.
        (3, 1, 0x12, 1, 40_000, 10), // Wrong acknowledgement.
        (4, 1, 0x14, 0, 40_001, 10), // Wrong client port.
        (5, 1, 0x14, 0, 40_000, 20), // Different capture scope.
        (6, 1, 0x12, 0, 40_000, 10),
        (7, 1, 0x12, 0, 40_000, 10), // Retransmitted reply.
        (8, 2, 0x02, 0, 40_000, 10),
        (9, 2, 0x14, 0, 40_000, 10),
        (10, 1, 0x02, 0, 40_000, 10), // Retry after the matched SYN-ACK.
    ] {
        engine.update(&tcp_frame(no, host, flags, ack, port, vlan));
    }
    for host in 3..=12 {
        engine.update(&tcp_frame(u64::from(host) + 8, host, 0x02, 0, 40_000, 10));
    }
    let finding = engine.findings.ids.iter().find(|f| f.alert.signature == "Horizontal host scan").unwrap();
    assert_eq!(finding.alert.pkt_no, 20);
    assert!(finding.alert.detail.contains("matched replies at alert time: SYN-ACK=1, RST-ACK=1"));
    assert!(finding.alert.detail.contains("handshake completion and intent unverified"));
    assert_eq!(finding.related_packets, [2, 6, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19]);
    engine.update(&tcp_frame(21, 12, 0x12, 0, 40_000, 10));
    assert!(!engine.findings.ids.iter().any(|f| f.alert.signature == "Horizontal host scan"));
}

#[test]
fn tcp_scan_retries_do_not_extend_the_evidence_window_but_new_attempts_can() {
    let mut engine = SecurityEngine::default();
    let mut packet = parse_ethernet(&[], 1, 1.0);
    packet.src = "192.0.2.1".into();
    packet.dst = "198.51.100.1".into();
    let key = scan_key(&packet, "TCP");
    engine.record_scan_probe(&packet, 443, "TCP", Some((40_000, 100)));
    packet.no = 2;
    packet.timestamp = 10.0;
    engine.record_scan_probe(&packet, 443, "TCP", Some((40_000, 100)));
    assert_eq!(engine.scan_sources[&key].probes[0].packet_no, 1);

    packet.no = 3;
    packet.timestamp = 11.0;
    engine.record_scan_probe(&packet, 443, "TCP", Some((40_000, 101)));
    assert_eq!(engine.scan_sources[&key].probes[0].packet_no, 3);

    packet.no = 4;
    packet.timestamp = 27.0;
    engine.record_scan_probe(&packet, 443, "TCP", Some((40_000, 101)));
    assert_eq!(engine.scan_sources[&key].probes[0].packet_no, 4);
}

#[test]
fn unique_probe_and_latch_state_are_bounded_within_one_scan_window() {
    let mut engine = SecurityEngine::default();
    let mut packet = parse_ethernet(&[], 1, 1.0);
    packet.src = "192.0.2.1".into();
    for host in 1..=100 {
        packet.dst = format!("198.51.100.{host}");
        for port in 1..=SCAN_UNIQUE_THRESHOLD as u16 {
            engine.record_scan_probe(&packet, port, "TCP", None);
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
                    engine.record_scan_probe(&packet, if vertical { target } else { 443 }, "TCP", None);
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

#[test]
fn late_syn_repeats_do_not_create_a_spike_but_new_sequences_do() {
    let mut engine = SecurityEngine::default();
    let mut packet = parse_ethernet(&[], 1, 1.0);
    packet.src = "192.0.2.1".into();
    packet.dst = "198.51.100.1".into();
    for sequence in 0..100 {
        packet.timestamp = if sequence < 50 { 1.0 } else { 2.1 };
        engine.record_syn_arrival(&packet, 443, 40_000, sequence);
        packet.no += 1;
    }
    assert!(engine.ids_alerts.is_empty());

    packet.timestamp = 3.2;
    for sequence in 0..100 {
        engine.record_syn_arrival(&packet, 443, 40_000, sequence);
        packet.no += 1;
    }
    assert!(engine.ids_alerts.is_empty());
    for sequence in 100..200 {
        engine.record_syn_arrival(&packet, 443, 40_000, sequence);
        packet.no += 1;
    }
    let finding = engine.findings.ids.last().unwrap();
    assert_eq!(engine.ids_alerts.len(), 1);
    assert_eq!(finding.alert.pkt_no, 300);
    assert_eq!(finding.related_packets, (201..300).collect::<Vec<_>>());

    packet.timestamp = 5.3;
    for sequence in 0..100 {
        engine.record_syn_arrival(&packet, 443, 40_000, sequence);
        packet.no += 1;
    }
    assert_eq!(engine.ids_alerts.len(), 2);
    assert_eq!(engine.findings.ids.last().unwrap().related_packets, (301..400).collect::<Vec<_>>());
}

#[test]
fn sustained_syn_activity_keeps_retry_memory_bounded() {
    let mut engine = SecurityEngine::default();
    let mut packet = parse_ethernet(&[], 1, 1.0);
    packet.src = "192.0.2.1".into();
    packet.dst = "198.51.100.1".into();
    for sequence in 0..MAX_SYN_HISTORY_PER_TARGET * 2 {
        engine.record_syn_arrival(&packet, 443, 40_000, sequence as u32);
        packet.no += 1;
    }
    assert_eq!(engine.ids_alerts.len(), 1);
    let state = engine.syn_flood_targets.values().next().unwrap();
    assert_eq!(state.attempts.len(), MAX_SYN_HISTORY_PER_TARGET);
    assert_eq!(state.attempts.first().unwrap().packet_no, MAX_SYN_HISTORY_PER_TARGET as u64 + 1);
}

#[test]
fn scan_and_syn_findings_never_join_evidence_across_capture_interfaces_or_sections() {
    use crate::net::packet::CaptureMetadata;

    for (mode, threshold) in [
        ("horizontal", SCAN_UNIQUE_THRESHOLD),
        ("vertical", SCAN_UNIQUE_THRESHOLD),
        ("echo", SCAN_UNIQUE_THRESHOLD),
        ("syn", SYN_FLOOD_THRESHOLD),
    ] {
        let mut engine = SecurityEngine::default();
        let mut packet = parse_ethernet(&[], 1, 1.0);
        packet.src = "192.0.2.1".into();
        let half = threshold as u64 / 2;
        let mut observe = |engine: &mut SecurityEngine, section_id, interface_id| {
            packet.capture = Some(CaptureMetadata {
                timestamp: None,
                captured_length: 60,
                wire_length: 60,
                link_type: 1,
                interface_id,
                section_id,
                interface_name: None,
                comments: Vec::new(),
            });
            for _ in 0..half {
                let frame = packet.no;
                packet.dst = match mode {
                    "horizontal" | "echo" => format!("198.51.100.{frame}"),
                    _ => "198.51.100.1".into(),
                };
                match mode {
                    "horizontal" => engine.record_scan_probe(&packet, 443, "TCP", None),
                    "vertical" => engine.record_scan_probe(&packet, frame as u16, "TCP", None),
                    "echo" => engine.record_echo_request(&packet, "ICMP"),
                    _ => engine.record_syn_arrival(&packet, 443, 40_000, frame as u32),
                }
                packet.no += 1;
            }
        };
        observe(&mut engine, 0, 0);
        observe(&mut engine, 0, 1);
        observe(&mut engine, 1, 0);
        assert!(engine.findings.ids.is_empty(), "{mode}");
        observe(&mut engine, 0, 0);
        observe(&mut engine, 0, 1);
        let findings = &engine.findings.ids;
        assert_eq!(findings.len(), 2, "{mode}");
        assert_ne!(findings[0].correlation_key, findings[1].correlation_key, "{mode}");
        assert_eq!(findings[0].alert.pkt_no, 4 * half);
        assert_eq!(findings[0].related_packets, (1..=half).chain(3 * half + 1..4 * half).collect::<Vec<_>>());
        assert_eq!(findings[1].alert.pkt_no, 5 * half);
        assert_eq!(findings[1].related_packets, (half + 1..=2 * half)
            .chain(4 * half + 1..5 * half).collect::<Vec<_>>());
    }
}
