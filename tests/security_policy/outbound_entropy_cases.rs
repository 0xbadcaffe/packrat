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
