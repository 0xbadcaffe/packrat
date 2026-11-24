use super::*;
use crate::net::parser::parse_ethernet;

fn scan_syn(sequence: u32) -> Option<ScanTcpProbe> {
    Some(ScanTcpProbe { source_port: 40_000, sequence, ..Default::default() })
}

#[test]
fn scan_reply_does_not_mutate_either_probe_when_acknowledgment_is_ambiguous() {
    let mut engine = SecurityEngine::default();
    let mut packet = parse_ethernet(&[], 1, 1.0);
    packet.src = "192.0.2.1".into();
    for frame in 1..=12 {
        packet.no = frame;
        packet.dst = format!("198.51.100.{frame}");
        let mut attempt = scan_syn(100).unwrap();
        attempt.payload_length = 5;
        engine.record_scan_probe(&packet, 443, "TCP", Some(attempt), false);
    }
    let key = scan_key(&packet, "TCP");
    packet.no = 13;
    engine.record_scan_probe(&packet, 443, "TCP", scan_syn(102), false);
    packet.no = 14;
    std::mem::swap(&mut packet.src, &mut packet.dst);
    let reply = TcpSignal {
        flags: 0x12, sequence: 500, acknowledgement: 103, payload_length: 0,
        source_port: 443, destination_port: 40_000, complete: true,
    };
    assert!(!engine.record_scan_reply(&packet, reply, false));
    assert_eq!(engine.scan_sources[&key].pending_final_acks, 0);
    assert!(engine.findings.ids_evidence.is_empty());
    packet.no = 15;
    assert!(engine.record_scan_reply(&packet, TcpSignal { acknowledgement: 106, ..reply }, false));
    assert_eq!(engine.findings.ids_evidence[0].evidence_frame, 15);
}

#[test]
fn scan_retains_only_scoped_reply_evidence_present_when_the_alert_opens() {
    let tcp_frame = |no, target, flags, ack: u32, client_port: u16, vlan| {
        let client = [192, 0, 2, 1];
        let host = [198, 51, 100, target];
        let (src, dst, sport, dport) = if matches!(flags, 0x02 | 0x10 | 0x18) {
            (client, host, client_port, 443_u16)
        } else {
            (host, client, 443_u16, client_port)
        };
        let mut raw = vec![0_u8; 54];
        if flags == 0x18 {
            raw.extend_from_slice(b"application data");
        }
        raw[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        raw[14] = 0x45;
        let ip_length = (raw.len() - 14) as u16;
        raw[16..18].copy_from_slice(&ip_length.to_be_bytes());
        raw[22] = 64;
        raw[23] = 6;
        raw[26..30].copy_from_slice(&src);
        raw[30..34].copy_from_slice(&dst);
        raw[34..36].copy_from_slice(&sport.to_be_bytes());
        raw[36..38].copy_from_slice(&dport.to_be_bytes());
        let sequence = if matches!(flags, 0x10 | 0x18) { 0 } else { u32::MAX };
        raw[38..42].copy_from_slice(&sequence.to_be_bytes());
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
        (11, 1, 0x18, 1, 40_000, 10), // Wrong acknowledgement, even with data.
        (12, 1, 0x10, 0, 40_000, 20), // Different capture scope.
        (13, 2, 0x10, 0, 40_000, 10), // Reset, not a matched SYN-ACK.
        (14, 1, 0x18, 0, 40_000, 10), // Valid third handshake packet carries data.
    ] {
        engine.update(&tcp_frame(no, host, flags, ack, port, vlan));
    }
    for host in 3..=12 {
        engine.update(&tcp_frame(u64::from(host) + 12, host, 0x02, 0, 40_000, 10));
    }
    let finding = engine.findings.ids.iter().find(|f| f.alert.signature == "Horizontal host scan").unwrap();
    assert_eq!(finding.alert.pkt_no, 24);
    assert!(finding.alert.detail.contains("over 0.000s within a 15s observation window"));
    assert!(finding.alert.detail.contains("matched replies at alert time: SYN-ACK=1, RST-ACK=1"));
    assert!(finding.alert.detail.contains("matched final ACKs=1; missing ACKs do not prove failure"));
    assert_eq!(finding.related_packets, [2, 6, 14, 8, 9, 15, 16, 17, 18, 19, 20, 21, 22, 23]);
    assert!(engine.scan_sources.values().all(|state| state.pending_final_acks == 0));
    engine.update(&tcp_frame(25, 12, 0x12, 0, 40_000, 10));
    assert!(!engine.findings.ids.iter().any(|f| f.alert.signature == "Horizontal host scan"));
    let [update] = engine.findings.ids_evidence.as_slice() else { panic!("expected one follow-up") };
    assert_eq!((update.opening_frame, update.probe_frame, update.evidence_frame), (24, 24, 25));
    assert_eq!(update.signature, "Horizontal host scan");
    for (no, ack, vlan) in [(26, 0, 20), (27, 1, 10), (28, 0, 10)] {
        engine.update(&tcp_frame(no, 12, 0x12, ack, 40_000, vlan));
        assert!(engine.findings.ids_evidence.is_empty());
    }
}

#[test]
fn pending_scan_acks_are_removed_by_probe_replacement_expiration_and_eviction() {
    for change in ["replace", "expire", "evict", "reset"] {
        let mut engine = SecurityEngine::default();
        let mut probe = parse_ethernet(&[], 1, 1.0);
        probe.src = "192.0.2.1".into();
        probe.dst = "198.51.100.1".into();
        let key = scan_key(&probe, "TCP");
        engine.record_scan_probe(&probe, 443, "TCP", scan_syn(100), false);
        let mut reply = probe.clone();
        std::mem::swap(&mut reply.src, &mut reply.dst);
        reply.no = 2;
        let signal = TcpSignal {
            flags: 0x12, sequence: 200, acknowledgement: 101,
            source_port: 443, destination_port: 40_000, complete: true, payload_length: 0,
        };
        engine.record_scan_reply(&reply, signal, false);
        engine.record_scan_reply(&reply, signal, false);
        assert_eq!(engine.scan_sources[&key].pending_final_acks, 1);

        probe.no = 3;
        match change {
            "reset" => {
                reply.no = 3;
                engine.record_scan_reply(&reply, signal, true);
            }
            "expire" => {
                probe.timestamp += SCAN_WINDOW_SECS + 1.0;
                engine.record_scan_probe(&probe, 443, "TCP", scan_syn(101), false);
            }
            "evict" => {
                probe.timestamp = 2.0;
                for index in 0..MAX_SCAN_PROBES_PER_SOURCE {
                    probe.dst = format!("198.51.{}.{index}", index / 256);
                    engine.record_scan_probe(&probe, 1_000 + index as u16, "TCP", scan_syn(101), false);
                    probe.no += 1;
                }
            }
            _ => engine.record_scan_probe(&probe, 443, "TCP", scan_syn(101), false),
        }
        assert_eq!(engine.scan_sources[&key].pending_final_acks, 0, "{change}");
    }
}

#[test]
fn linked_scan_attempt_retention_is_bounded_and_releases_evicted_pending_acks() {
    let mut state = SourceScanState::default();
    let mut packet = parse_ethernet(&[], 1, 1.0);
    for frame in 1..=65 {
        packet.no = frame;
        let mut probe = ScanProbe::new(&packet, 443, Some(ScanTcpProbe {
            syn_ack: Some(ScanSynAck { order: (1.0, frame), sequence: 200,
                payload_length: 0, client_next_sequence: 101 }),
            ..Default::default()
        }));
        probe.horizontal_opening = Some(100);
        state.pending_final_acks += 1;
        state.retain_linked_probe(probe);
    }
    assert_eq!(state.linked_probes.len(), 64);
    assert_eq!(state.linked_probes.front().unwrap().packet_no, 2);
    assert_eq!(state.pending_final_acks, 64);
}

#[test]
fn linked_scan_attempts_expire_and_do_not_count_as_new_targets_or_extend_retries() {
    let mut engine = SecurityEngine::default();
    let mut probe = parse_ethernet(&[], 1, 1.0);
    probe.src = "192.0.2.1".into();
    for host in 1..=12 {
        probe.no = host;
        probe.dst = format!("198.51.100.{host}");
        engine.record_scan_probe(&probe, 443, "TCP", scan_syn(100), false);
    }
    let key = scan_key(&probe, "TCP");
    let mut reply = probe.clone();
    std::mem::swap(&mut reply.src, &mut reply.dst);
    let signal = TcpSignal {
        flags: 0x12, sequence: 500, acknowledgement: 101,
        source_port: 443, destination_port: 40_000, complete: true, payload_length: 0,
    };
    reply.no = 13;
    engine.record_scan_reply(&reply, signal, false);
    probe.no = 14;
    engine.record_scan_probe(&probe, 443, "TCP", scan_syn(200), false);
    probe.no = 15;
    engine.record_scan_probe(&probe, 443, "TCP", scan_syn(100), false);
    let state = &engine.scan_sources[&key];
    assert_eq!(state.probes.len(), 12);
    assert_eq!(state.probes.last().unwrap().packet_no, 14);
    assert_eq!(state.linked_probes.len(), 1);
    assert_eq!(state.linked_probes[0].packet_no, 12);
    assert_eq!(state.pending_final_acks, 1);

    reply.no = 16;
    reply.timestamp += SCAN_WINDOW_SECS + 1.0;
    let updates = engine.findings.ids_evidence.len();
    engine.record_scan_reply(&reply, signal, true);
    assert_eq!(engine.findings.ids_evidence.len(), updates);
    probe.no = 17;
    probe.timestamp = reply.timestamp;
    engine.record_scan_probe(&probe, 443, "TCP", scan_syn(100), false);
    let state = &engine.scan_sources[&key];
    assert_eq!(state.probes.len(), 1);
    assert!(state.linked_probes.is_empty());
    assert_eq!(state.pending_final_acks, 0);
}

#[test]
fn tcp_scan_retries_do_not_extend_the_evidence_window_but_new_attempts_can() {
    let mut engine = SecurityEngine::default();
    let mut packet = parse_ethernet(&[], 1, 1.0);
    packet.src = "192.0.2.1".into();
    packet.dst = "198.51.100.1".into();
    let key = scan_key(&packet, "TCP");
    engine.record_scan_probe(&packet, 443, "TCP", scan_syn(100), false);
    packet.no = 2;
    packet.timestamp = 10.0;
    engine.record_scan_probe(&packet, 443, "TCP", scan_syn(100), false);
    assert_eq!(engine.scan_sources[&key].probes[0].packet_no, 1);

    packet.no = 3;
    packet.timestamp = 11.0;
    engine.record_scan_probe(&packet, 443, "TCP", scan_syn(101), false);
    assert_eq!(engine.scan_sources[&key].probes[0].packet_no, 3);

    packet.no = 4;
    packet.timestamp = 27.0;
    engine.record_scan_probe(&packet, 443, "TCP", scan_syn(101), false);
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
            engine.record_scan_probe(&packet, port, "TCP", None, false);
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
                    engine.record_echo_request(&packet, "ICMP", false);
                } else {
                    engine.record_scan_probe(&packet, if vertical { target } else { 443 }, "TCP", None, false);
                }
                packet.no += 1;
            }
            engine.ids_alerts.iter().filter(|alert| alert.signature == signature).count()
        };

        assert_eq!(observe(&mut engine, 1.0, 1..=12), 1);
        let initial_key = engine.findings.ids.last().unwrap().correlation_key.clone();
        assert_eq!(observe(&mut engine, 12.0, 1..=6), 1);
        // Six probes remain active, so reaching the threshold again is not a new burst.
        assert_eq!(observe(&mut engine, 17.0, 13..=18), 1);
        assert_eq!(observe(&mut engine, 25.0, 18..=18), 1);
        // One lingering probe must not suppress a new burst of eleven probes.
        assert_eq!(observe(&mut engine, 33.0, 19..=29), 2);
        let latest = engine.findings.ids.last().unwrap();
        assert_eq!(latest.alert.pkt_no, 36);
        assert_eq!(latest.related_packets, (25..=35).collect::<Vec<_>>());
        assert_ne!(latest.correlation_key, initial_key);
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
            engine.record_syn_arrival(&packet, 443, 40_000, sequence.unwrap_or(packet.no as u32), false);
            packet.no += 1;
        }
        engine.ids_alerts.len()
    };
    assert_eq!(observe(&mut engine, 1.0, 50, None), 0);
    assert_eq!(observe(&mut engine, 1.5, 50, None), 1);
    let initial_key = engine.findings.ids.last().unwrap().correlation_key.clone();
    assert_eq!(observe(&mut engine, 2.25, 50, None), 1);
    assert_eq!(observe(&mut engine, 3.0, 1, None), 1);
    assert_eq!(observe(&mut engine, 3.5, 120, Some(151)), 1);
    assert_eq!(observe(&mut engine, 3.5, 99, None), 2);
    let renewed = engine.findings.ids.last().unwrap();
    assert_eq!(renewed.alert.pkt_no, 370);
    assert_eq!(renewed.related_packets, std::iter::once(151).chain(272..370).collect::<Vec<_>>());
    assert_ne!(renewed.correlation_key, initial_key);
}

#[test]
fn late_syn_repeats_do_not_create_a_spike_but_new_sequences_do() {
    let mut engine = SecurityEngine::default();
    let mut packet = parse_ethernet(&[], 1, 1.0);
    packet.src = "192.0.2.1".into();
    packet.dst = "198.51.100.1".into();
    for sequence in 0..100 {
        packet.timestamp = if sequence < 50 { 1.0 } else { 2.1 };
        engine.record_syn_arrival(&packet, 443, 40_000, sequence, false);
        packet.no += 1;
    }
    assert!(engine.ids_alerts.is_empty());

    packet.timestamp = 3.2;
    for sequence in 0..100 {
        engine.record_syn_arrival(&packet, 443, 40_000, sequence, false);
        packet.no += 1;
    }
    assert!(engine.ids_alerts.is_empty());
    for sequence in 100..200 {
        engine.record_syn_arrival(&packet, 443, 40_000, sequence, false);
        packet.no += 1;
    }
    let finding = engine.findings.ids.last().unwrap();
    assert_eq!(engine.ids_alerts.len(), 1);
    assert_eq!(finding.alert.pkt_no, 300);
    assert_eq!(finding.related_packets, (201..300).collect::<Vec<_>>());

    packet.timestamp = 5.3;
    for sequence in 0..100 {
        engine.record_syn_arrival(&packet, 443, 40_000, sequence, false);
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
        engine.record_syn_arrival(&packet, 443, 40_000, sequence as u32, false);
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
                    "horizontal" => engine.record_scan_probe(&packet, 443, "TCP", None, false),
                    "vertical" => engine.record_scan_probe(&packet, frame as u16, "TCP", None, false),
                    "echo" => engine.record_echo_request(&packet, "ICMP", false),
                    _ => engine.record_syn_arrival(&packet, 443, 40_000, frame as u32, false),
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
