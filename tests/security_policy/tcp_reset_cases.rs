use super::{SecurityEngine, ipv4_tcp_packet};
use packrat_tui::engine::AnalysisCore;
use packrat_tui::net::{packet::Packet, parser::parse_ethernet};

const TITLE: &str = "TCP payload after reset";

#[test]
fn incomplete_tcp_capture_is_not_a_malformed_header() {
    const MALFORMED: &str = "Malformed TCP header";
    let mut snaplen = ipv4_tcp_packet(1, 100, 0x04, b"");
    snaplen.bytes.truncate(34 + 13);
    let mut first_fragment = ipv4_tcp_packet(2, 100, 0x04, b"");
    first_fragment.bytes[16..18].copy_from_slice(&36_u16.to_be_bytes());
    first_fragment.bytes[20] = 0x20;
    first_fragment.bytes.truncate(34 + 16);
    let mut short_datagram = first_fragment.clone();
    short_datagram.no = 3;
    short_datagram.timestamp = 3.0;
    short_datagram.bytes[20] = 0;
    let mut invalid_offset = ipv4_tcp_packet(4, 100, 0x04, b"");
    invalid_offset.bytes[46] = 0x40;
    let mut invalid_ip_length = ipv4_tcp_packet(5, 100, 0x04, b"");
    invalid_ip_length.bytes[16..18].copy_from_slice(&19_u16.to_be_bytes());

    let mut core = AnalysisCore::default();
    for packet in [
        &snaplen,
        &first_fragment,
        &short_datagram,
        &invalid_offset,
        &invalid_ip_length,
    ] {
        core.analyze(packet);
    }
    let evidence: Vec<_> = core.security.ids_alerts.iter()
        .filter(|alert| alert.signature == MALFORMED)
        .map(|alert| alert.pkt_no)
        .collect();
    assert_eq!(evidence, [3, 4]);
}

fn ipv6_tcp_packet(no: u64, sequence: u32, flags: u8, payload: &[u8]) -> Packet {
    let tcp = ipv4_tcp_packet(no, sequence, flags, payload);
    let mut options_and_tcp = vec![6, 0, 0, 0, 0, 0, 0, 0];
    options_and_tcp.extend_from_slice(&tcp.bytes[34..]);
    let frame = super::cases_3::ipv6_frame(1, 60, &options_and_tcp);
    parse_ethernet(&frame, no, no as f64)
}

#[test]
fn tcp_header_evidence_uses_declared_lengths_after_complete_ip_headers() {
    let fixtures: [(fn(u64, u32, u8, &[u8]) -> Packet, usize); 2] =
        [(ipv4_tcp_packet, 34), (ipv6_tcp_packet, 62)];
    for (packet, transport) in fixtures {
        let mut security = SecurityEngine::default();
        for (frame, captured, offset, expected) in [
            (1, 12, 0xb0, None),
            (2, 13, 0x60, None),
            (3, 13, 0xb0, Some("exceeds the IP transport length")),
            (4, 13, 0x40, Some("smaller than 20 bytes")),
        ] {
            let mut packet = packet(frame, 100, 0x18, &[0; 20]);
            packet.bytes[transport + 12] = offset;
            packet.bytes.truncate(transport + captured);
            let batch = security.inspect(&packet);
            let finding = batch.ids.iter().find(|finding| finding.alert.signature == "Malformed TCP header");
            assert_eq!(finding.is_some(), expected.is_some());
            if let Some(reason) = expected {
                assert!(finding.unwrap().alert.detail.contains(reason));
            }
        }
    }

    let mut incomplete_chain = ipv6_tcp_packet(5, 100, 0x18, &[0; 20]);
    incomplete_chain.bytes.truncate(60);
    let mut fragmented = ipv6_tcp_packet(6, 100, 0x18, &[0; 20]);
    fragmented.bytes[20] = 44;
    fragmented.bytes[57] = 1;
    fragmented.bytes[74] = 0xb0;
    for packet in [incomplete_chain, fragmented] {
        assert!(SecurityEngine::default().inspect(&packet).ids.iter()
            .all(|finding| finding.alert.signature != "Malformed TCP header"));
    }
}

#[test]
fn malformed_tcp_findings_do_not_share_review_state_across_paths_ports_or_reasons() {
    use packrat_tui::analysis::alert_center::AlertDisposition;
    use packrat_tui::net::packet::{CaptureMetadata, CaptureTimestamp, TimestampResolution};

    let make = |no, vlan, interface_id, port: u16, offset| {
        let mut raw = ipv4_tcp_packet(no, 100, 0x18, &[]).bytes;
        raw[36..38].copy_from_slice(&port.to_be_bytes());
        raw[46] = offset;
        raw.splice(12..12, [0x81, 0, 0, vlan]);
        let mut packet = parse_ethernet(&raw, no, no as f64);
        packet.capture = Some(CaptureMetadata {
            timestamp: Some(CaptureTimestamp { ticks: no, resolution: TimestampResolution::Decimal(0), offset_seconds: 0 }),
            captured_length: raw.len() as u32, wire_length: raw.len() as u32,
            link_type: 1, section_id: 0, interface_id, interface_name: None, comments: Vec::new(),
        });
        packet
    };
    let mut core = AnalysisCore::default();
    core.analyze(&make(1, 10, 0, 443, 0x40));
    let first = core.alert_center.items.iter().find(|alert| alert.title == "Malformed TCP header").unwrap();
    let id = first.id;
    assert!(core.alert_center.set_disposition(id, None, AlertDisposition::Benign));
    for packet in [
        make(2, 10, 0, 443, 0x40), make(3, 20, 0, 443, 0x40),
        make(4, 10, 1, 443, 0x40), make(5, 10, 0, 445, 0x40),
        make(6, 10, 0, 443, 0x60),
    ] {
        core.analyze(&packet);
    }
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == "Malformed TCP header").collect();
    assert_eq!(alerts.len(), 5);
    assert_eq!(alerts[0].hit_count, 2);
    assert_eq!(alerts[0].packet_refs, [1, 2]);
    assert_eq!(alerts[0].disposition, AlertDisposition::Benign);
    for (alert, frame) in alerts[1..].iter().zip(3..=6) {
        assert_eq!(alert.packet_refs, [frame]);
        assert_eq!(alert.disposition, AlertDisposition::New);
    }
    assert!(alerts[3].detail.contains("10.0.0.5:445"));
    assert!(alerts[4].detail.contains("exceeds the IP transport length"));
}

#[test]
fn detects_tcp_payload_continuing_after_reset() {
    let mut core = AnalysisCore::default();
    core.analyze(&ipv4_tcp_packet(1, 90, 0x18, b"previous"));
    core.analyze(&ipv4_tcp_packet(2, 100, 0x04, b""));
    core.analyze(&ipv4_tcp_packet(3, 90, 0x18, b"previous"));
    assert!(!core.alert_center.items.iter().any(|alert| alert.title == TITLE));

    core.analyze(&ipv4_tcp_packet(4, 101, 0x18, b"later"));
    let alert = core.alert_center.items.iter().find(|alert| alert.title == TITLE).unwrap();
    assert_eq!(alert.packet_refs, [2, 4]);
    assert_eq!(alert.packet_no, 4);
    assert_eq!(alert.severity, "MEDIUM");
    let rule = alert.provenance.as_ref().unwrap();
    assert_eq!(rule.rule_id, "tcp.payload_after_observed_reset");
    assert_eq!(rule.revision, 8);
    assert_eq!(rule.confidence.to_string(), "Heuristic");
    assert!(alert.detail.contains("payload seq 101 followed reset frame #2 (same direction, seq 100)"));
    assert!(alert.detail.contains("reset acceptance and on-wire ordering unverified"));
}

#[test]
fn peer_payload_is_a_low_severity_lead_and_does_not_hide_same_sender_evidence() {
    let mut core = AnalysisCore::default();
    core.analyze(&ipv4_tcp_packet(1, 100, 0x04, b""));

    let mut peer = ipv4_tcp_packet(2, 200, 0x18, b"in flight");
    for offset in 0..4 { peer.bytes.swap(26 + offset, 30 + offset); }
    for offset in 0..2 { peer.bytes.swap(34 + offset, 36 + offset); }
    core.analyze(&parse_ethernet(&peer.bytes, 2, 2.0));
    let alert = core.alert_center.items.iter().find(|alert| alert.title == TITLE).unwrap();
    let id = alert.id;
    assert_eq!(alert.severity, "LOW");
    assert_eq!(alert.packet_refs, [1, 2]);
    assert!(alert.detail.contains("opposite direction"));
    assert!(alert.detail.contains("peer payload may already have been in flight"));

    peer.bytes[38..42].copy_from_slice(&209_u32.to_be_bytes());
    core.analyze(&parse_ethernet(&peer.bytes, 3, 3.0));
    core.analyze(&ipv4_tcp_packet(4, 101, 0x18, b"same sender"));
    let mut matching = core.alert_center.items.iter().filter(|alert| alert.title == TITLE);
    let alert = matching.next().unwrap();
    assert_eq!(alert.id, id);
    assert_eq!(alert.hit_count, 2);
    assert_eq!(alert.severity, "MEDIUM");
    assert_eq!(alert.packet_refs, [1, 2, 4]);
    assert!(alert.detail.contains("same direction"));
    assert!(matching.next().is_none());
    assert!(core.incidents.incidents.is_empty());
}

#[test]
fn tcp_reset_correlation_ignores_other_vlans_earlier_payload_and_new_connections() {
    let mut security = SecurityEngine::default();
    let mut reset = ipv4_tcp_packet(10, 100, 0x04, b"");
    reset.vlan_id = Some(10);
    security.update(&reset);

    let mut earlier = ipv4_tcp_packet(11, 101, 0x18, b"earlier timestamp");
    earlier.timestamp = 9.0;
    earlier.vlan_id = Some(10);
    let mut other_vlan = ipv4_tcp_packet(12, 120, 0x18, b"other VLAN");
    other_vlan.vlan_id = Some(20);
    let mut new_syn = ipv4_tcp_packet(13, 300, 0x02, b"");
    new_syn.vlan_id = Some(10);
    let mut new_data = ipv4_tcp_packet(14, 301, 0x18, b"new connection");
    new_data.vlan_id = Some(10);
    for packet in [earlier, other_vlan, new_syn, new_data] {
        let findings = security.inspect(&packet);
        assert!(findings.ids.iter().all(|finding| finding.alert.signature != TITLE));
    }
}

#[test]
fn tcp_reset_correlation_uses_frame_order_when_capture_timestamps_tie() {
    let packet = |frame, seq, flags, payload: &[u8]| {
        let mut packet = ipv4_tcp_packet(frame, seq, flags, payload);
        packet.timestamp = 1.0;
        packet
    };
    let mut engine = SecurityEngine::default();
    engine.update(&packet(10, 100, 0x04, b""));
    engine.update(&packet(9, 90, 0x18, b"earlier"));
    engine.update(&packet(8, 80, 0x04, b""));
    assert!(engine.ids_alerts.iter().all(|alert| alert.signature != TITLE));
    let batch = engine.inspect(&packet(11, 101, 0x18, b"later"));
    let alert = batch.ids.iter().find(|finding| finding.alert.signature == TITLE).unwrap();
    assert_eq!(alert.related_packets, [10]);
    assert_eq!(alert.alert.pkt_no, 11);

    let mut engine = SecurityEngine::default();
    engine.update(&packet(5, 50, 0x18, b"current"));
    engine.update(&packet(4, 40, 0x04, b""));
    engine.update(&packet(6, 60, 0x18, b"later"));
    assert!(engine.ids_alerts.iter().all(|alert| alert.signature != TITLE));
}

#[test]
fn tcp_reset_correlation_does_not_use_an_incomplete_ip_datagram() {
    let mut security = SecurityEngine::default();
    let mut partial_reset = ipv4_tcp_packet(1, 100, 0x04, b"");
    partial_reset.bytes[20] = 0x20; // IPv4 more-fragments flag.
    security.update(&partial_reset);
    let findings = security.inspect(&ipv4_tcp_packet(2, 101, 0x18, b"normal traffic"));
    assert!(findings.ids.iter().all(|finding| finding.alert.signature != TITLE));
}

#[test]
fn conflicting_tcp_retransmission_links_both_frames_across_sequence_wrap() {
    let mut core = AnalysisCore::default();
    core.analyze(&ipv4_tcp_packet(1, u32::MAX - 2, 0x18, b"ABCD"));
    core.analyze(&ipv4_tcp_packet(2, 0, 0x18, b"D"));
    assert!(core.alert_center.items.iter().all(|alert| alert.title != "Conflicting TCP retransmission"));
    core.analyze(&ipv4_tcp_packet(3, 0, 0x18, b"X"));
    let alert = core.alert_center.items.iter().find(|alert| alert.title == "Conflicting TCP retransmission").unwrap();
    assert_eq!(alert.packet_refs, [1, 3]);
    assert!(alert.detail.contains("TCP sequence 0 (1 overlapping bytes compared)"));
    assert!(alert.detail.contains("receiver outcome unverified"));
    assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "tcp.conflicting_retransmission");
    assert!(core.incidents.incidents.is_empty());
}

#[test]
fn conflicting_tcp_retransmission_accounts_for_syn_before_payload() {
    let mut engine = SecurityEngine::default();
    engine.update(&ipv4_tcp_packet(1, 100, 0x02, b"abc"));
    assert!(engine.inspect(&ipv4_tcp_packet(2, 101, 0x18, b"abc")).ids.is_empty());
    let mut other_vlan = ipv4_tcp_packet(3, 102, 0x18, b"X");
    other_vlan.vlan_id = Some(100);
    assert!(engine.inspect(&other_vlan).ids.is_empty());
    let findings = engine.inspect(&ipv4_tcp_packet(4, 102, 0x18, b"X"));
    let alert = findings.ids.iter().find(|finding| finding.alert.signature == "Conflicting TCP retransmission").unwrap();
    assert_eq!(alert.related_packets, [1]);
    assert!(alert.alert.detail.contains("TCP sequence 102"));
}

#[test]
fn tcp_integrity_preserves_recent_evidence_after_the_first_128_segments() {
    let mut engine = SecurityEngine::default();
    for frame in 1..=130 {
        engine.update(&ipv4_tcp_packet(frame, frame as u32 * 16, 0x18, b"original"));
    }
    let expired = engine.inspect(&ipv4_tcp_packet(131, 16, 0x18, b"other"));
    assert!(expired.ids.is_empty());
    for frame in 132..=270 {
        assert!(engine.inspect(&ipv4_tcp_packet(frame, 16, 0x18, b"other")).ids.is_empty());
    }
    let findings = engine.inspect(&ipv4_tcp_packet(271, 130 * 16, 0x18, b"changed"));
    let finding = findings.ids.iter().find(|finding| finding.alert.signature == "Conflicting TCP retransmission").unwrap();
    assert_eq!(finding.related_packets, [130]);
    assert_eq!(finding.alert.pkt_no, 271);
}

#[test]
fn ipv6_tcp_integrity_links_reset_and_conflict_evidence() {
    let mut core = AnalysisCore::default();
    core.analyze(&ipv6_tcp_packet(1, 100, 0x18, b"original"));
    core.analyze(&ipv6_tcp_packet(2, 200, 0x04, b""));
    core.analyze(&ipv6_tcp_packet(3, 100, 0x18, b"original"));
    assert!(core.alert_center.items.iter().all(|alert| alert.title != TITLE));
    core.analyze(&ipv6_tcp_packet(4, 102, 0x18, b"changed"));
    let resets = core.alert_center.items.iter().find(|alert| alert.title == TITLE).unwrap();
    assert_eq!(resets.packet_refs, [2, 4]);
    assert!(resets.detail.contains("[2001:db8::1]:50000"));
    let conflict = core.alert_center.items.iter().find(|alert| alert.title == "Conflicting TCP retransmission").unwrap();
    assert_eq!(conflict.packet_refs, [1, 4]);
    assert_eq!(conflict.provenance.as_ref().unwrap().revision, 5);
}

#[test]
fn periodic_traffic_counts_new_tcp_sequences_not_identical_retransmissions() {
    use super::PacketFixtureExt;
    let signature = "Periodic fixed-size traffic";
    let fixtures: [fn(u64, u32, u8, &[u8]) -> Packet; 2] = [ipv4_tcp_packet, ipv6_tcp_packet];
    for packet in fixtures {
        let mut repeated = SecurityEngine::default();
        let mut progressive = SecurityEngine::default();
        for index in 0..7 {
            let frame = index + 1;
            let time = index as f64 * 15.0;
            let retry = packet(frame, 100, 0x18, b"same").with_number_and_timestamp(frame, time);
            assert!(repeated.inspect(&retry).ids.iter().all(|hit| hit.alert.signature != signature));
            let mut data = packet(frame, 100 + index as u32 * 4, 0x18, b"same")
                .with_number_and_timestamp(frame, time);
            data.protocol = if frame % 2 == 0 { "TCP" } else { "TLS" }.into();
            let result = progressive.inspect(&data);
            let finding = result.ids.iter().find(|hit| hit.alert.signature == signature);
            if frame == 7 {
                assert_eq!(finding.unwrap().related_packets, [1, 2, 3, 4, 5, 6]);
            } else {
                assert!(finding.is_none());
            }
        }
    }
}

#[test]
fn periodic_traffic_excludes_partial_retries_without_hiding_fresh_packets() {
    use super::PacketFixtureExt;
    let title = "Periodic fixed-size traffic";
    let fixtures: [fn(u64, u32, u8, &[u8]) -> Packet; 2] = [ipv4_tcp_packet, ipv6_tcp_packet];
    for packet in fixtures {
        let payload = [1; 16];
        let mut partial = SecurityEngine::default();
        let mut interleaved = SecurityEngine::default();
        for index in 0..7_u64 {
            let time = index as f64 * 15.0;
            let frame = index + 1;
            let mostly_repeated = packet(frame, 100 + index as u32, 0x18, &payload)
                .with_number_and_timestamp(frame, time);
            assert!(partial.inspect(&mostly_repeated).ids.iter().all(|hit| hit.alert.signature != title));

            let fresh_frame = index * 2 + 1;
            let sequence = 100 + index as u32 * 17;
            let clean = packet(fresh_frame, sequence, 0x18, &payload)
                .with_number_and_timestamp(fresh_frame, time);
            let result = interleaved.inspect(&clean);
            let finding = result.ids.iter().find(|hit| hit.alert.signature == title);
            if index == 6 {
                assert_eq!(finding.unwrap().related_packets, [1, 3, 5, 7, 9, 11]);
            } else {
                assert!(finding.is_none());
                let retry = packet(fresh_frame + 1, sequence + 1, 0x18, &payload)
                    .with_number_and_timestamp(fresh_frame + 1, time + 7.0);
                assert!(interleaved.inspect(&retry).ids.iter().all(|hit| hit.alert.signature != title));
            }
        }
    }
}

#[test]
fn ipv6_tcp_integrity_ignores_incomplete_or_fragmented_resets() {
    for fragmented in [false, true] {
        let mut engine = SecurityEngine::default();
        let mut reset = ipv6_tcp_packet(1, 100, 0x04, b"");
        if fragmented {
            reset.bytes[20] = 44;
            reset.bytes[57] = 1;
        } else {
            reset.bytes.pop();
        }
        engine.update(&reset);
        let result = engine.inspect(&ipv6_tcp_packet(2, 101, 0x18, b"ordinary"));
        assert!(result.ids.iter().all(|finding| finding.alert.signature != TITLE));
    }
}

#[test]
fn post_reset_rule_ignores_unchanged_data_split_across_segments() {
    let mut core = AnalysisCore::default();
    core.analyze(&ipv4_tcp_packet(1, u32::MAX - 1, 0x18, b"ab"));
    core.analyze(&ipv4_tcp_packet(2, 0, 0x18, b"cd"));
    core.analyze(&ipv4_tcp_packet(3, 2, 0x04, b""));
    core.analyze(&ipv4_tcp_packet(4, u32::MAX - 1, 0x18, b"abcd"));
    core.analyze(&ipv4_tcp_packet(5, u32::MAX, 0x18, b"bc"));
    assert!(core.alert_center.items.iter().all(|alert| alert.title != TITLE));

    core.analyze(&ipv4_tcp_packet(6, u32::MAX, 0x18, b"bcde"));
    let finding = core.alert_center.items.iter().find(|alert| alert.title == TITLE).unwrap();
    assert_eq!(finding.packet_refs, [3, 6]);
    let flow = finding.flow.unwrap();
    assert_eq!(flow.source.to_string(), "203.0.113.9:50000");
    assert_eq!(flow.destination.to_string(), "10.0.0.5:443");
}

#[test]
fn post_reset_rule_does_not_treat_a_gap_as_known_bytes() {
    let mut engine = SecurityEngine::default();
    engine.update(&ipv6_tcp_packet(1, 100, 0x18, b"ab"));
    engine.update(&ipv6_tcp_packet(2, 104, 0x18, b"ef"));
    engine.update(&ipv6_tcp_packet(3, 106, 0x04, b""));
    let result = engine.inspect(&ipv6_tcp_packet(4, 100, 0x18, b"abcdef"));
    let finding = result.ids.iter().find(|finding| finding.alert.signature == TITLE).unwrap();
    assert_eq!(finding.related_packets, [3]);
}

#[test]
fn syn_ack_and_repeated_syn_preserve_opening_payload_evidence() {
    let mut engine = SecurityEngine::default();
    engine.update(&ipv4_tcp_packet(1, 100, 0x02, b"abcd"));
    let mut response = ipv4_tcp_packet(2, 500, 0x02, b"");
    for offset in 0..4 { response.bytes.swap(26 + offset, 30 + offset); }
    for offset in 0..2 { response.bytes.swap(34 + offset, 36 + offset); }
    engine.update(&response);
    response.no = 3;
    response.timestamp = 3.0;
    response.bytes[47] = 0x12;
    engine.update(&response);
    engine.update(&ipv4_tcp_packet(4, 100, 0x02, b"abcd"));
    let result = engine.inspect(&ipv4_tcp_packet(5, 102, 0x18, b"X"));
    let finding = result.ids.iter().find(|finding| finding.alert.signature == "Conflicting TCP retransmission").unwrap();
    assert_eq!(finding.related_packets, [1]);
}

#[test]
fn new_openings_keep_post_reset_alerts_distinct_on_a_reused_tuple() {
    let mut core = AnalysisCore::default();
    core.analyze(&ipv4_tcp_packet(1, 10, 0x02, b""));
    core.analyze(&ipv4_tcp_packet(2, 11, 0x04, b""));
    core.analyze(&ipv4_tcp_packet(3, 11, 0x18, b"first"));
    core.analyze(&ipv4_tcp_packet(4, 20, 0x02, b""));
    let mut delayed = ipv4_tcp_packet(5, 21, 0x18, b"stale");
    delayed.timestamp = 3.5;
    core.analyze(&delayed);
    core.analyze(&ipv4_tcp_packet(6, 21, 0x18, b"fresh"));
    assert!(core.alert_center.items.iter().all(|alert| alert.title != "Conflicting TCP retransmission"));
    core.analyze(&ipv4_tcp_packet(7, 30, 0x04, b""));
    core.analyze(&ipv4_tcp_packet(8, 31, 0x18, b"second"));
    let findings: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == TITLE).collect();
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].packet_refs, [2, 3]);
    assert_eq!(findings[1].packet_refs, [7, 8]);
}
