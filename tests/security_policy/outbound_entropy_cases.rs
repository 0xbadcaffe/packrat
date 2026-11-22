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
#[case(false)]
#[case(true)]
fn repeated_tcp_bytes_do_not_accumulate_entropy_evidence(#[case] resegmented: bool) {
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
            .any(|alert| alert.title == "Large asymmetric outbound transfer")
    );
    assert!(
        alerts
            .iter()
            .all(|alert| alert.title != "High-entropy outbound transfer")
    );

    for frame in 36..=39 {
        core.analyze(&outbound_tcp(frame, &data));
    }
    let alert = core
        .alert_center
        .items
        .iter()
        .find(|alert| alert.title == "High-entropy outbound transfer")
        .unwrap();
    assert_eq!(alert.packet_refs, [1, 36, 37, 38, 39]);
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
    for (rule, frames) in [
        ("traffic.asymmetric_outbound", (10..=17).collect::<Vec<_>>()),
        ("traffic.high_entropy_outbound", (1..=5).collect()),
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
        assert_eq!(
            alert.provenance.as_ref().unwrap().confidence.to_string(),
            "Heuristic"
        );
    }
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
        let packet = outbound_tcp(no, &vec![0; wire - 54]);
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
        if no % 2 == 0 { packet.bytes.pop(); }
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
