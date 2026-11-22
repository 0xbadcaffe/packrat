use super::*;

#[test]
fn detects_stp_topology_change_and_lldp_identity_change() {
    let mut security = SecurityEngine::default();
    let mut bpdu = vec![0_u8; 22];
    bpdu[..6].copy_from_slice(&[0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]);
    bpdu[6..12].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
    bpdu[12..14].copy_from_slice(&7_u16.to_be_bytes());
    bpdu[14..17].copy_from_slice(&[0x42, 0x42, 0x03]);
    bpdu[20] = 0x80;
    security.update(&packet("STP", 0, "", bpdu));
    security.update(&lldp_packet(2, [0, 1, 2, 3, 4, 5], b"switch-a"));
    security.update(&lldp_packet(3, [0, 1, 2, 3, 4, 5], b"switch-b"));

    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "STP topology change")
    );
    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "LLDP chassis identity changed")
    );
}

#[test]
fn detects_periodic_fixed_size_traffic() {
    let mut security = SecurityEngine::default();
    for index in 0..7_u64 {
        security.update(&behavior_packet(
            index + 1,
            index as f64 * 10.0,
            120,
            vec![0; 120],
        ));
    }
    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "Periodic fixed-size traffic")
    );

    let mut irregular = SecurityEngine::default();
    for (index, timestamp) in [0.0, 2.0, 9.0, 11.0, 27.0, 31.0, 60.0]
        .into_iter()
        .enumerate()
    {
        irregular.update(&behavior_packet(
            index as u64 + 1,
            timestamp,
            100 + index * 17,
            vec![0; 100],
        ));
    }
    assert!(
        !irregular
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "Periodic fixed-size traffic")
    );
}

#[test]
fn periodic_traffic_ignores_empty_tcp_segments_but_keeps_payload_samples() {
    let mut engine = SecurityEngine::default();
    let signature = "Periodic fixed-size traffic";
    for index in 0..7 {
        let timestamp = index as f64 * 15.4;
        let ack = ipv4_tcp_packet(2 * index + 1, 100, 0x10, &[]);
        engine.update(&ack.with_number_and_timestamp(2 * index + 1, timestamp));
        assert!(!engine.ids_alerts.iter().any(|alert| alert.signature == signature));

        let data = ipv4_tcp_packet(2 * index + 2, 100 + index as u32 * 12, 0x18, &[1; 12]);
        let result = engine.inspect(&data.with_number_and_timestamp(2 * index + 2, timestamp + 1.0));
        let finding = result.ids.iter().find(|finding| finding.alert.signature == signature);
        if index < 6 {
            assert!(finding.is_none());
        } else {
            assert_eq!(finding.unwrap().related_packets, [2, 4, 6, 8, 10, 12]);
        }
    }
}

#[test]
fn periodic_traffic_alerts_once_per_conversation_and_keeps_directional_evidence() {
    use packrat_tui::engine::AnalysisCore;

    let mut core = AnalysisCore::default();
    for sample in 0..7 {
        for source_port in [50000, 50001] {
            let no = sample * 4 + if source_port == 50000 { 1 } else { 3 };
            let mut outbound = behavior_packet(no, sample as f64 * 10.0, 120, vec![0; 120]);
            outbound.src_port = Some(source_port);
            let mut inbound = outbound.clone();
            std::mem::swap(&mut inbound.src, &mut inbound.dst);
            std::mem::swap(&mut inbound.src_port, &mut inbound.dst_port);
            inbound.no += 1;
            inbound.timestamp += 0.5;
            core.analyze(&outbound);
            core.analyze(&inbound);
        }
        if sample < 6 {
            assert!(!core.alert_center.items.iter().any(|alert| alert.title == "Periodic fixed-size traffic"));
        }
    }
    let alerts: Vec<_> = core.alert_center.items.iter()
        .filter(|alert| alert.title == "Periodic fixed-size traffic").collect();
    assert_eq!(alerts.len(), 2);
    assert_ne!(alerts[0].correlation_key, alerts[1].correlation_key);
    assert_eq!(alerts[0].severity, "MEDIUM");
    assert!(alerts.iter().all(|alert| alert.flow.is_none()));
    assert_eq!(alerts[0].packet_refs, [1, 5, 9, 13, 17, 21, 25]);
    assert_eq!(alerts[1].packet_refs, [3, 7, 11, 15, 19, 23, 27]);
}

#[test]
fn periodic_alert_reports_the_ranges_measured_from_its_evidence() {
    let mut engine = SecurityEngine::default();
    for (index, (timestamp, length)) in [
        (0.0, 120), (9.0, 119), (20.0, 122), (f64::NAN, 500),
        (30.0, 121), (39.0, 118), (50.0, 120),
    ].into_iter().enumerate() {
        engine.update(&behavior_packet(index as u64 + 1, timestamp, length, vec![0; length]));
    }
    let result = engine.inspect(&behavior_packet(8, 60.0, 120, vec![0; 120]));
    let finding = result.ids.iter().find(|finding| finding.alert.signature == "Periodic fixed-size traffic").unwrap();
    assert_eq!(finding.related_packets, [1, 2, 3, 5, 6, 7]);
    assert!(finding.alert.detail.contains("7 packets"));
    assert!(finding.alert.detail.contains("over 60.0s; gaps 9.0-11.0s (mean 10.0s), sizes 118-122 bytes"));
    assert!(finding.alert.detail.contains("does not establish command-and-control"));
}

#[test]
fn periodic_alert_only_cites_the_regular_run_after_an_irregular_prefix() {
    let mut engine = SecurityEngine::default();
    for (index, timestamp) in [0.0, 1.0, 3.0, 14.0].into_iter().enumerate() {
        engine.update(&behavior_packet(index as u64 + 1, timestamp, 400, vec![0; 400]));
    }
    for index in 0..7 {
        let timestamp = 60.0 + index as f64 * 10.0;
        let result = engine.inspect(&behavior_packet(index + 5, timestamp, 120, vec![0; 120]));
        let finding = result.ids.iter().find(|finding| finding.alert.signature == "Periodic fixed-size traffic");
        if index == 6 {
            let finding = finding.unwrap();
            assert_eq!(finding.alert.pkt_no, 11);
            assert_eq!(finding.related_packets, [5, 6, 7, 8, 9, 10]);
            assert!(finding.alert.detail.contains("gaps 10.0-10.0s (mean 10.0s), sizes 120-120 bytes"));
        } else {
            assert!(finding.is_none());
        }
    }
}

#[test]
fn periodic_traffic_uses_wire_lengths_and_separates_capture_scopes() {
    use packrat_tui::{
        engine::AnalysisCore,
        net::packet::{CaptureMetadata, CaptureTimestamp, TimestampResolution},
    };

    let packet = |no, timestamp, wire_length, section_id, interface_id| {
        let mut packet = behavior_packet(no, timestamp, 120, vec![0; 120]);
        packet.capture = Some(CaptureMetadata {
            timestamp: Some(CaptureTimestamp {
                ticks: timestamp as u64,
                resolution: TimestampResolution::Decimal(0),
                offset_seconds: 0,
            }),
            captured_length: 120,
            wire_length,
            link_type: 1,
            section_id,
            interface_id,
            interface_name: None,
            comments: Vec::new(),
        });
        packet
    };
    let is_periodic = |item: &packrat_tui::analysis::alert_center::AlertItem| {
        item.title == "Periodic fixed-size traffic"
    };
    let mut truncated = AnalysisCore::default();
    for index in 0..7 {
        truncated.analyze(&packet(index + 1, index as f64 * 10.0,
            if index % 2 == 0 { 200 } else { 900 }, 0, 0));
    }
    assert!(!truncated.alert_center.items.iter().any(is_periodic));

    for alternate_scope in [(0, 1), (1, 0)] {
        let mut scoped = AnalysisCore::default();
        for index in 0..7 {
            let (section, interface) = if index % 2 == 0 { (0, 0) } else { alternate_scope };
            scoped.analyze(&packet(index + 1, index as f64 * 10.0, 900, section, interface));
        }
        assert!(!scoped.alert_center.items.iter().any(is_periodic));

        for index in 4..7 {
            scoped.analyze(&packet(index + 4, index as f64 * 20.0, 900, 0, 0));
        }
        let alert = scoped.alert_center.items.iter().find(|item| is_periodic(item)).unwrap();
        assert_eq!(alert.packet_refs, [1, 3, 5, 7, 8, 9, 10]);
        assert_eq!(alert.provenance.as_ref().unwrap().revision, 6);
    }
}

#[test]
fn detects_large_high_entropy_outbound_transfer() {
    let mut security = SecurityEngine::default();
    let mut core = packrat_tui::engine::AnalysisCore::default();
    let encrypted_like = (0..60_000)
        .map(|index| ((index * 73) % 256) as u8)
        .collect::<Vec<_>>();
    for index in 0..17_u64 {
        let packet = behavior_packet(
            index + 1,
            index as f64 / 10.0,
            60_000,
            encrypted_like.clone(),
        );
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
        let alert = core.alert_center.items.iter().find(|alert| {
            alert.provenance.as_ref().is_some_and(|provenance| provenance.rule_id == rule)
        }).unwrap();
        assert_eq!(alert.packet_refs, frames);
        assert_eq!(alert.provenance.as_ref().unwrap().confidence.to_string(), "Heuristic");
    }
}

#[test]
fn outbound_volume_does_not_combine_interfaces_and_keeps_reverse_evidence() {
    use packrat_tui::{
        engine::AnalysisCore,
        net::packet::{CaptureMetadata, CaptureTimestamp, TimestampResolution},
    };
    let mut core = AnalysisCore::default();
    for no in 1..=27 {
        let mut packet = behavior_packet(no, no as f64, 60_000, vec![0; 60_000]);
        let scope = if no <= 18 { (no - 1) % 2 } else { 0 };
        if no == 19 {
            std::mem::swap(&mut packet.src, &mut packet.dst);
            std::mem::swap(&mut packet.src_port, &mut packet.dst_port);
        }
        packet.capture = Some(CaptureMetadata {
            timestamp: Some(CaptureTimestamp {
                ticks: no, resolution: TimestampResolution::Decimal(0), offset_seconds: 0,
            }),
            captured_length: 60_000, wire_length: 60_000, link_type: 1,
            interface_id: scope as u32, section_id: 0, interface_name: None, comments: vec![],
        });
        core.analyze(&packet);
        if no < 27 {
            assert!(!core.alert_center.items.iter().any(|alert| alert.title == "Large asymmetric outbound transfer"));
        }
    }
    let alert = core.alert_center.items.iter().find(|alert| alert.title == "Large asymmetric outbound transfer").unwrap();
    assert_eq!(alert.packet_refs, (19..=27).collect::<Vec<_>>());
}

#[test]
fn sparse_transfers_do_not_cross_hour_boundaries_and_late_packets_cannot_restore_expired_volume() {
    let mut core = packrat_tui::engine::AnalysisCore::default();
    let transfer_count = |core: &packrat_tui::engine::AnalysisCore| {
        core.alert_center.items.iter().filter(|a| a.title == "Large asymmetric outbound transfer").count()
    };
    let packet = |no, time| behavior_packet(no, time, 60_000, vec![0; 60_000]);
    for index in 0..20 {
        core.analyze(&packet(index + 1, index as f64 * 240.0));
    }
    assert_eq!(transfer_count(&core), 0);
    core.analyze(&packet(21, 1.0));
    core.analyze(&packet(22, 4_561.0));
    assert_eq!(transfer_count(&core), 0);
    core.analyze(&packet(23, 4_562.0));
    assert_eq!(transfer_count(&core), 1);
    let alert = core.alert_center.items.iter()
        .find(|a| a.title == "Large asymmetric outbound transfer").unwrap();
    assert_eq!(alert.packet_refs, [15, 16, 17, 18, 19, 20, 22, 23]);
    assert!(alert.detail.contains("rolling hour"));
}

#[test]
fn group_traffic_does_not_trigger_beacon_or_outbound_transfer_rules() {
    let mut security = SecurityEngine::default();
    for destination in ["255.255.255.255", "224.0.0.7", "ff02::1"] {
        for i in 0..18 {
            let mut sample = behavior_packet(i, i as f64 * 10.0, 60_000, Vec::new());
            sample.dst = destination.into();
            if destination.contains(':') {
                sample.src = "fe80::5".into();
            }
            security.update(&sample);
        }
    }
    assert!(!security.ids_alerts.iter().any(|alert| matches!(
        alert.signature,
        "Periodic fixed-size traffic"
            | "Large asymmetric outbound transfer"
            | "High-entropy outbound transfer"
    )));
}

#[test]
fn ordinary_llmnr_queries_do_not_indicate_poisoning() {
    let mut security = SecurityEngine::default();
    for destination in ["224.0.0.252", "ff02::1:3"] {
        let mut query = packet("LLMNR", 5355, "Standard query", vec![0; 20]);
        query.dst = destination.into();
        security.update(&query);
    }
    assert!(security.ids_alerts.is_empty());
}

#[test]
fn http_authentication_burst_requires_distinct_wire_401_responses() {
    let mut security = SecurityEngine::default();
    for i in 1..=5_u64 {
        let mut packet = ipv4_tcp_packet(i, i as u32 * 100, 0x18, b"not an HTTP response");
        packet.info = "TCP Seq=401".into();
        security.update(&packet);
    }
    assert!(security.brute_force.is_empty());

    let response = |no: u64, sequence: u32| {
        let mut packet = ipv4_tcp_packet(no, sequence, 0x18, b"HTTP/1.1 401 Unauthorized\r\n\r\n");
        packet.bytes[34..36].copy_from_slice(&80_u16.to_be_bytes());
        packet.bytes[36..38].copy_from_slice(&50000_u16.to_be_bytes());
        packet.src_port = Some(80);
        packet.dst_port = Some(50000);
        packet.protocol = "HTTP".into();
        packet
    };
    for i in 6..=10 {
        security.update(&response(i, 10_000));
    }
    assert!(security.brute_force.is_empty());

    for i in 11..=14 {
        security.update(&response(i, i as u32 * 1000));
    }
    assert_eq!(security.brute_force.len(), 1);
    let alert = &security.brute_force[0];
    assert_eq!((alert.src_ip.as_str(), alert.dst_ip.as_str(), alert.port), ("10.0.0.5", "203.0.113.9", 80));
    assert_eq!(alert.attempts, 5);
    assert_eq!(alert.packet_refs, [6, 11, 12, 13, 14]);

    for i in 50..=54 {
        security.update(&response(i, i as u32 * 1000));
    }
    assert_eq!(security.brute_force.len(), 2);
    assert_eq!(security.brute_force[1].packet_refs, [50, 51, 52, 53, 54]);

    let mut core = packrat_tui::engine::AnalysisCore::default();
    for i in 6..=14 {
        let sequence = if i <= 10 { 10_000 } else { i as u32 * 1000 };
        core.analyze(&response(i, sequence));
    }
    let exports = core.alert_center.drain_pending_exports();
    let alert = exports
        .iter()
        .find(|alert| alert.title == "HTTP authentication burst")
        .expect("HTTP burst exported");
    assert_eq!(alert.severity, "MEDIUM");
    assert_eq!(alert.hit_count, 1);
    assert_eq!(alert.packet_no, 14);
    assert_eq!(alert.packet_refs, [6, 11, 12, 13, 14]);
}

#[test]
fn detects_new_dhcp_server_authority_per_vlan() {
    let mut security = SecurityEngine::default();
    security.update(&dhcp_packet(
        1,
        2,
        [0, 1, 2, 3, 4, 5],
        [10, 11, 12, 13, 14, 15],
        Some([10, 0, 0, 1]),
    ));
    security.update(&dhcp_packet(
        2,
        2,
        [0, 1, 2, 3, 4, 5],
        [10, 11, 12, 13, 14, 15],
        Some([10, 0, 0, 1]),
    ));
    security.update(&dhcp_packet(
        3,
        2,
        [0, 1, 2, 3, 4, 6],
        [10, 11, 12, 13, 14, 15],
        Some([10, 0, 0, 2]),
    ));

    assert_eq!(
        security
            .ids_alerts
            .iter()
            .filter(|alert| alert.signature == "DHCP server identity changed")
            .count(),
        1
    );
}

#[test]
fn detects_dhcp_starvation_identity_burst() {
    let mut security = SecurityEngine::default();
    for index in 0..64_u64 {
        let client = [
            0x02,
            0,
            0,
            (index >> 16) as u8,
            (index >> 8) as u8,
            index as u8,
        ];
        security.update(&dhcp_packet(index + 1, 1, client, client, None));
    }

    assert!(security.ids_alerts.iter().any(|alert| {
        alert.signature == "DHCP client identity burst"
            && alert.severity == packrat_tui::net::security::Severity::Medium
    }));
}

#[test]
fn detects_http_request_smuggling_framing_ambiguities() {
    for request in [
        b"POST / HTTP/1.1\r\nHost: example\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".as_slice(),
        b"POST / HTTP/1.1\r\nHost: example\r\nContent-Length: 5\r\nContent-Length: 9\r\n\r\n".as_slice(),
        b"POST / HTTP/1.1\r\nHost: example\r\nTransfer-Encoding : chunked\r\n\r\n".as_slice(),
    ] {
        let mut security = SecurityEngine::default();
        security.update(&http_packet(1, 100, request));
        assert!(security.ids_alerts.iter().any(|alert| {
            alert.signature == "HTTP request smuggling ambiguity"
                && alert.severity == packrat_tui::net::security::Severity::Critical
        }));
    }
}

#[test]
fn accumulates_split_http_headers_and_allows_unambiguous_framing() {
    let first = b"POST /upload HTTP/1.1\r\nHost: example\r\nContent-Length: 5\r\n";
    let second = b"Transfer-Encoding: chunked\r\n\r\n";
    let mut split = SecurityEngine::default();
    split.update(&http_packet(1, 100, first));
    assert!(
        !split
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "HTTP request smuggling ambiguity")
    );
    split.update(&http_packet(2, 100 + first.len() as u32, second));
    assert!(
        split
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "HTTP request smuggling ambiguity")
    );

    let mut valid = SecurityEngine::default();
    valid.update(&http_packet(
        1,
        100,
        b"POST /upload HTTP/1.1\r\nHost: example\r\nContent-Length: 5\r\n\r\nhello",
    ));
    assert!(
        !valid
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "HTTP request smuggling ambiguity")
    );
}
