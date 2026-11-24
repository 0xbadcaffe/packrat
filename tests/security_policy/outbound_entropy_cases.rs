use super::*;

#[rstest]
#[case(false)]
#[case(true)]
fn outbound_entropy_does_not_count_bytes_past_the_transport_payload(#[case] udp: bool) {
    let mut security = SecurityEngine::default();
    let trailer: Vec<_> = (0..60_000).map(|index| (index * 73 % 256) as u8).collect();
    for frame in 1..=5 {
        let mut packet = outbound_tcp(frame, &[]);
        if udp {
            packet.bytes.truncate(42);
            packet.bytes[16..18].copy_from_slice(&28_u16.to_be_bytes());
            packet.bytes[23] = 17;
            packet.bytes[38..40].copy_from_slice(&8_u16.to_be_bytes());
        }
        packet.bytes.extend_from_slice(&trailer);
        security.update(&packrat_tui::net::parser::parse_ethernet(
            &packet.bytes,
            frame,
            frame as f64,
        ));
    }
    assert!(
        security
            .ids_alerts
            .iter()
            .all(|alert| alert.signature != "High-entropy outbound transfer")
    );
}

fn outbound_tcp(frame: u64, payload: &[u8]) -> Packet {
    let mut packet = ipv4_tcp_packet(frame, frame as u32 * 60_000, 0x18, payload);
    packet.bytes[26..30].copy_from_slice(&[10, 0, 0, 5]);
    packet.bytes[30..34].copy_from_slice(&[198, 51, 100, 10]);
    packrat_tui::net::parser::parse_ethernet(&packet.bytes, frame, frame as f64 / 10.0)
}

#[rstest]
#[case(false, 17, "Large asymmetric outbound transfer")]
#[case(true, 5, "High-entropy outbound transfer")]
fn outbound_thresholds_cannot_mix_tag_paths(#[case] varied: bool, #[case] threshold: u64, #[case] title: &str) {
    let mut core = packrat_tui::engine::AnalysisCore::default();
    let payload: Vec<_> = (0..60_000).map(|index| if varied { (index * 73 % 256) as u8 } else { 0 }).collect();
    let trigger = threshold + threshold / 2;
    for frame in 1..=trigger {
        let packet = outbound_tcp(frame, &payload);
        let mut raw = packet.bytes;
        let tpid = if frame <= threshold && frame % 2 == 0 { 0x88a8_u16 } else { 0x8100_u16 };
        raw.splice(12..12, [tpid, 20].into_iter().flat_map(u16::to_be_bytes));
        core.analyze(&packrat_tui::net::parser::parse_ethernet(&raw, frame, packet.timestamp));
        if frame < trigger {
            assert!(core.alert_center.items.iter().all(|alert| alert.title != title));
        }
    }
    let alert = core.alert_center.items.iter().find(|alert| alert.title == title).unwrap();
    let eligible = (1..=trigger).filter(|&frame| frame > threshold || frame % 2 == 1).collect::<Vec<_>>();
    assert_eq!(alert.packet_refs, eligible[eligible.len().saturating_sub(8)..]);
}

#[rstest]
#[case(false)]
#[case(true)]
fn repeated_tcp_bytes_do_not_accumulate_outbound_evidence(#[case] resegmented: bool) {
    let mut core = packrat_tui::engine::AnalysisCore::default();
    let data: Vec<_> = (0..60_000).map(|index| (index * 73 % 256) as u8).collect();
    core.analyze(&outbound_tcp(1, &data));
    for frame in 2..=35 {
        let offset = if resegmented && frame % 2 == 0 {
            30_000
        } else {
            0
        };
        let size = if resegmented { 30_000 } else { data.len() };
        let mut retransmission = outbound_tcp(frame, &data[offset..offset + size]);
        let sequence = 60_000 + offset as u32;
        retransmission.bytes[38..42].copy_from_slice(&sequence.to_be_bytes());
        core.analyze(&retransmission);
    }
    let alerts = &core.alert_center.items;
    assert!(
        alerts
            .iter()
            .all(|alert| alert.title != "Large asymmetric outbound transfer")
    );
    assert!(
        alerts
            .iter()
            .all(|alert| alert.title != "High-entropy outbound transfer")
    );

    for frame in 36..=51 {
        core.analyze(&outbound_tcp(frame, &data));
    }
    let alert = core
        .alert_center
        .items
        .iter()
        .find(|alert| alert.title == "High-entropy outbound transfer")
        .unwrap();
    assert_eq!(alert.packet_refs, [1, 36, 37, 38, 39]);
    assert_eq!(alert.severity, "MEDIUM");
    assert!(alert.detail.contains("exfiltration is unverified"));
    let volume = core.alert_center.items.iter().find(|alert| alert.title == "Large asymmetric outbound transfer").unwrap();
    assert_eq!(volume.packet_refs, (44..=51).collect::<Vec<_>>());
    assert_eq!(volume.first_packet, 51);
    assert!(volume.detail.contains("excluding recognized outbound TCP payload retries"));
}

#[test]
fn resegmented_tcp_retries_count_only_new_payload_and_still_detect_real_transfers() {
    let data: Vec<_> = (0..60_040).map(|index| (index * 73 % 256) as u8).collect();
    let mut core = packrat_tui::engine::AnalysisCore::default();
    let rule = |alert: &packrat_tui::analysis::alert_center::AlertItem| {
        alert.provenance.as_ref().is_some_and(|item| matches!(item.rule_id.as_str(),
            "traffic.high_entropy_outbound" | "traffic.asymmetric_outbound"))
    };
    for frame in 1..=35 {
        let offset = frame as usize - 1;
        let mut packet = outbound_tcp(frame, &data[offset..offset + 60_000]);
        let sequence = 60_000 + offset as u32;
        packet.bytes[38..42].copy_from_slice(&sequence.to_be_bytes());
        core.analyze(&packet);
    }
    assert!(!core.alert_center.items.iter().any(rule));

    for frame in 36..=51 {
        core.analyze(&outbound_tcp(frame, &data[..60_000]));
    }
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| rule(alert)).collect();
    assert_eq!(alerts.len(), 2);
    let entropy = alerts.iter().find(|alert| alert.title == "High-entropy outbound transfer").unwrap();
    assert_eq!(entropy.first_packet, 39);
    assert_eq!(entropy.packet_refs, [1, 36, 37, 38, 39]);
    let volume = alerts.iter().find(|alert| alert.title == "Large asymmetric outbound transfer").unwrap();
    assert_eq!(volume.first_packet, 51);
}

#[test]
fn entropy_counts_new_suffixes_of_partial_retransmissions() {
    const TITLE: &str = "High-entropy outbound transfer";
    let data: Vec<_> = (0..270_000).map(|index| (index * 73 % 256) as u8).collect();
    let mut security = SecurityEngine::default();
    for frame in 1..=8 {
        let offset = (frame as usize - 1) * 30_000;
        let mut packet = outbound_tcp(frame, &data[offset..offset + 60_000]);
        let sequence = 60_000 + offset as u32;
        packet.bytes[38..42].copy_from_slice(&sequence.to_be_bytes());
        security.update(&packet);
        if frame < 8 {
            assert!(security.ids_alerts.iter().all(|alert| alert.signature != TITLE));
        }
    }
    let alert = security.ids_alerts.iter().find(|alert| alert.signature == TITLE).unwrap();
    assert_eq!(alert.pkt_no, 8);
    assert!(alert.detail.contains("270000 high-entropy outbound transport payload bytes"));
}

#[test]
fn detects_large_high_entropy_outbound_transfer() {
    let mut security = SecurityEngine::default();
    let mut core = packrat_tui::engine::AnalysisCore::default();
    let encrypted_like = (0..60_000)
        .map(|index| ((index * 73) % 256) as u8)
        .collect::<Vec<_>>();
    for index in 0..17_u64 {
        let packet = outbound_tcp(index + 1, &encrypted_like);
        security.update(&packet);
        core.analyze(&packet);
    }

    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "Large asymmetric outbound transfer")
    );
    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "High-entropy outbound transfer")
    );
    for (rule, severity, revision, frames) in [
        ("traffic.asymmetric_outbound", "MEDIUM", 11, (10..=17).collect::<Vec<_>>()),
        ("traffic.high_entropy_outbound", "MEDIUM", 10, (1..=5).collect()),
    ] {
        let alert = core
            .alert_center
            .items
            .iter()
            .find(|alert| {
                alert
                    .provenance
                    .as_ref()
                    .is_some_and(|provenance| provenance.rule_id == rule)
            })
            .unwrap();
        assert_eq!(alert.packet_refs, frames);
        assert_eq!(alert.severity, severity);
        assert_eq!(alert.provenance.as_ref().unwrap().revision, revision);
        let flow = alert.flow.unwrap();
        assert_eq!(flow.transport, packrat_tui::analysis::alert_center::AlertTransport::Tcp);
        assert_eq!(flow.source.ip().to_string(), "10.0.0.5");
        assert_eq!(flow.destination.ip().to_string(), "198.51.100.10");
        assert_eq!(
            alert.provenance.as_ref().unwrap().confidence.to_string(),
            "Heuristic"
        );
    }
}

#[test]
fn renewed_entropy_transfer_keeps_a_reviewed_episode_separate() {
    use packrat_tui::analysis::alert_center::AlertDisposition;

    const TITLE: &str = "High-entropy outbound transfer";
    let mut core = packrat_tui::engine::AnalysisCore::default();
    let data: Vec<_> = (0..60_000).map(|index| (index * 73 % 256) as u8).collect();
    for frame in 1..=5 {
        core.analyze(&outbound_tcp(frame, &data));
    }
    let first = core.alert_center.items.iter().find(|a| a.title == TITLE).unwrap();
    let (id, scope) = (first.id, first.capture_id.clone());
    assert!(core.alert_center.set_disposition(id, scope.as_deref(), AlertDisposition::Benign));

    let mut keepalive = outbound_tcp(6, b"keepalive");
    keepalive.timestamp = 3_550.0;
    core.analyze(&keepalive);
    for frame in 7..=12 {
        let mut packet = outbound_tcp(frame, &data);
        packet.timestamp += 3_620.0;
        core.analyze(&packet);
    }

    let alerts: Vec<_> = core.alert_center.items.iter().filter(|a| a.title == TITLE).collect();
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0].id, id);
    assert_eq!(alerts[0].disposition, AlertDisposition::Benign);
    assert_eq!(alerts[0].packet_refs, [1, 2, 3, 4, 5]);
    assert_ne!(alerts[1].id, id);
    assert_eq!(alerts[1].disposition, AlertDisposition::New);
    assert_eq!(alerts[1].packet_refs, [7, 8, 9, 10, 11]);
}

#[test]
fn volume_rule_requires_a_reverse_baseline_to_report_an_observed_ratio() {
    const TITLE: &str = "Large asymmetric outbound transfer";
    let mut core = packrat_tui::engine::AnalysisCore::default();
    let payload = vec![0; 60_000];
    for frame in 1..=17 {
        core.analyze(&outbound_tcp(frame, &payload));
    }
    let alert = core.alert_center.items.iter().find(|alert| alert.title == TITLE).unwrap();
    let id = alert.id;
    assert_eq!(alert.severity, "MEDIUM");
    assert!(alert.detail.contains("no reverse bytes observed; asymmetry unverified"));
    assert!(!alert.detail.contains(":1"));

    let mut reverse = outbound_tcp(18, b"return traffic").bytes;
    for offset in 0..4 { reverse.swap(26 + offset, 30 + offset); }
    for offset in 0..2 { reverse.swap(34 + offset, 36 + offset); }
    core.analyze(&packrat_tui::net::parser::parse_ethernet(&reverse, 18, 1.8));
    core.analyze(&outbound_tcp(19, &payload));
    core.analyze(&outbound_tcp(20, &payload));
    let mut matching = core.alert_center.items.iter().filter(|alert| alert.title == TITLE);
    let alert = matching.next().unwrap();
    assert_eq!(alert.id, id);
    assert_eq!(alert.severity, "HIGH");
    assert_eq!(alert.hit_count, 2);
    assert_eq!(alert.packet_refs, (10..=19).collect::<Vec<_>>());
    assert!(alert.detail.contains("observed ratio across 68 captured reverse bytes"));
    assert!(matching.next().is_none());
}

#[test]
fn retries_in_the_reverse_direction_still_count_toward_the_volume_baseline() {
    let mut core = packrat_tui::engine::AnalysisCore::default();
    let payload = vec![0; 60_000];
    let mut reverse = outbound_tcp(1, &payload).bytes;
    for offset in 0..4 { reverse.swap(26 + offset, 30 + offset); }
    for offset in 0..2 { reverse.swap(34 + offset, 36 + offset); }
    for no in 1..=4 {
        core.analyze(&packrat_tui::net::parser::parse_ethernet(&reverse, no, no as f64 / 10.0));
    }
    for no in 5..=21 {
        core.analyze(&outbound_tcp(no, &payload));
    }
    assert!(core.alert_center.items.iter().all(|alert| alert.title != "Large asymmetric outbound transfer"));
}

#[test]
fn later_transfer_does_not_inherit_severity_or_evidence_from_an_expired_episode() {
    const TITLE: &str = "Large asymmetric outbound transfer";
    let mut core = packrat_tui::engine::AnalysisCore::default();
    let payload = vec![0; 60_000];
    let mut reverse = outbound_tcp(1, b"return traffic").bytes;
    for offset in 0..4 { reverse.swap(26 + offset, 30 + offset); }
    for offset in 0..2 { reverse.swap(34 + offset, 36 + offset); }
    core.analyze(&packrat_tui::net::parser::parse_ethernet(&reverse, 1, 0.1));
    for frame in 2..=35 {
        let mut packet = outbound_tcp(frame, &payload);
        if frame >= 19 {
            packet.timestamp += 3_601.0;
        }
        core.analyze(&packet);
    }
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == TITLE).collect();
    assert_eq!(alerts.len(), 2);
    assert_ne!(alerts[0].id, alerts[1].id);
    assert_eq!(alerts[0].severity, "HIGH");
    assert_eq!(alerts[0].packet_refs, [1, 11, 12, 13, 14, 15, 16, 17, 18]);
    assert_eq!(alerts[1].severity, "MEDIUM");
    assert_eq!(alerts[1].packet_refs, (28..=35).collect::<Vec<_>>());
}

#[test]
fn outbound_volume_counts_captured_bytes_above_the_display_length_limit() {
    use packrat_tui::net::{
        packet::{CaptureMetadata, CaptureTimestamp, TimestampResolution},
        parser::parse_captured,
    };

    const FRAME: usize = 65_535 + 14;
    const TOTAL: usize = 1_000_000;
    const TITLE: &str = "Large asymmetric outbound transfer";
    let mut complete = SecurityEngine::default();
    let mut truncated = SecurityEngine::default();
    for no in 1..=16 {
        let wire = if no < 16 { FRAME } else { TOTAL - 15 * FRAME };
        let mut packet = outbound_tcp(no, &vec![0; wire - 54]);
        let sequence = no as u32 * u32::from(u16::MAX);
        packet.bytes[38..42].copy_from_slice(&sequence.to_be_bytes());
        let parse = |len| parse_captured(&packet.bytes[..len], no, CaptureMetadata {
            timestamp: Some(CaptureTimestamp {
                ticks: no, resolution: TimestampResolution::Decimal(0), offset_seconds: 0,
            }),
            captured_length: len as u32, wire_length: wire as u32, link_type: 1,
            section_id: 0, interface_id: 0, interface_name: None, comments: Vec::new(),
        }).unwrap();
        complete.update(&parse(wire));
        truncated.update(&parse(wire - 1));
        assert!(truncated.ids_alerts.iter().all(|alert| alert.signature != TITLE));
        if no < 16 {
            assert!(complete.ids_alerts.iter().all(|alert| alert.signature != TITLE));
        }
    }
    let alert = complete.ids_alerts.iter().find(|alert| alert.signature == TITLE).unwrap();
    assert_eq!(alert.pkt_no, 16);
    assert!(alert.detail.contains("1000000 captured outbound bytes"));
}

#[test]
fn outbound_transfer_uses_wire_transport_when_display_labels_change() {
    let payload: Vec<_> = (0..60_000).map(|index| (index * 73 % 256) as u8).collect();
    for udp in [false, true] {
        let mut core = packrat_tui::engine::AnalysisCore::default();
        for no in 1..=17 {
            let mut packet = transfer_packet(no, &payload, udp);
            packet.protocol = match (udp, no % 2 == 0) {
                (false, false) => "TCP", (false, true) => "TLS",
                (true, false) => "UDP", (true, true) => "QUIC",
            }.into();
            core.analyze(&packet);
        }
        for (rule, first, expected) in [
            ("traffic.high_entropy_outbound", 5, (1..=5).collect::<Vec<_>>()),
            ("traffic.asymmetric_outbound", 17, (10..=17).collect()),
        ] {
            let findings: Vec<_> = core.alert_center.items.iter().filter(|alert| {
                alert.provenance.as_ref().is_some_and(|item| item.rule_id == rule)
            }).collect();
            assert_eq!(findings.len(), 1, "{rule}; UDP={udp}");
            assert_eq!(findings[0].first_packet, first);
            assert_eq!(findings[0].packet_refs, expected);
        }
    }
}

fn transfer_packet(no: u64, payload: &[u8], udp: bool) -> Packet {
    let mut packet = outbound_tcp(no, payload);
    if udp {
        packet.bytes.drain(42..54);
        packet.bytes[16..18].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
        packet.bytes[23] = 17;
        packet.bytes[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    }
    packet
}

#[test]
fn outbound_volume_does_not_combine_tcp_udp_or_unverified_transport() {
    let payload = vec![0; 60_000];
    let mut engine = SecurityEngine::default();
    for no in 1..=17 {
        let mut packet = transfer_packet(no, &payload, no % 2 == 0);
        // A captured UDP header still identifies its service when its payload is truncated.
        if no % 2 == 0 {
            let wire_length = packet.bytes.len() as u32;
            packet.bytes.pop();
            packet.capture = Some(packrat_tui::net::packet::CaptureMetadata {
                timestamp: None,
                captured_length: packet.bytes.len() as u32,
                wire_length,
                link_type: 1,
                section_id: 0,
                interface_id: 0,
                interface_name: None,
                comments: Vec::new(),
            });
        }
        packet.protocol = "TCP".into();
        engine.update(&packet);
    }
    for no in 18..=26 {
        let mut packet = transfer_packet(no, &payload, false);
        packet.bytes[47] = 0x18;
        packet.bytes[23] = 0;
        packet.protocol = "TCP".into();
        engine.update(&packet);
    }
    assert!(engine.ids_alerts.iter().all(|alert| alert.signature != "Large asymmetric outbound transfer"));
}

#[test]
fn outbound_tcp_ack_only_traffic_does_not_count_toward_transfer_volume() {
    const TITLE: &str = "Large asymmetric outbound transfer";
    let mut security = SecurityEngine::default();
    for no in 1..=19_000 {
        let mut ack = outbound_tcp(no, &[]);
        ack.bytes[47] = 0x10;
        security.update(&ack);
    }
    assert!(security.ids_alerts.iter().all(|alert| alert.signature != TITLE));

    let payload = vec![0; 60_000];
    for no in 19_001..=19_016 {
        security.update(&outbound_tcp(no, &payload));
    }
    assert!(security.ids_alerts.iter().all(|alert| alert.signature != TITLE));
    security.update(&outbound_tcp(19_017, &payload));
    let alert = security.ids_alerts.iter().find(|alert| alert.signature == TITLE).unwrap();
    assert_eq!(alert.pkt_no, 19_017);
    assert!(alert.detail.contains("payload-free TCP frames"));
}
