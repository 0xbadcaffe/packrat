use super::*;

#[test]
fn detects_stp_topology_change_and_lldp_identity_change() {
    let mut security = SecurityEngine::default();
    let mut bpdu = vec![0_u8; 22];
    bpdu[..6].copy_from_slice(&[0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]);
    bpdu[6..12].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
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
    assert_eq!(alerts[0].packet_refs, [1, 5, 9, 13, 17, 21, 25]);
    assert_eq!(alerts[1].packet_refs, [3, 7, 11, 15, 19, 23, 27]);
}

#[test]
fn detects_large_high_entropy_outbound_transfer() {
    let mut security = SecurityEngine::default();
    let encrypted_like = (0..60_000)
        .map(|index| ((index * 73) % 256) as u8)
        .collect::<Vec<_>>();
    for index in 0..17_u64 {
        security.update(&behavior_packet(
            index + 1,
            index as f64 / 10.0,
            60_000,
            encrypted_like.clone(),
        ));
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
fn detects_dns_nxdomain_burst_txt_abuse_and_external_resolver_use() {
    let mut security = SecurityEngine::default();
    for index in 0..20_u64 {
        let mut response = packet(
            "DNS",
            50000,
            "Response NXDOMAIN missing.example",
            vec![0; 100],
        );
        response.no = index + 1;
        response.timestamp = index as f64;
        response.src = "10.0.0.1".into();
        response.dst = "10.0.0.5".into();
        response.src_port = Some(53);
        response.dst_port = Some(50000);
        security.update(&response);
    }

    let mut txt = packet("DNS", 53, "Query TXT encoded.example", vec![0; 600]);
    txt.src = "10.0.0.5".into();
    txt.dst = "8.8.8.8".into();
    txt.length = 600;
    security.update(&txt);

    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "DNS NXDOMAIN burst")
    );
    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "Oversized DNS TXT traffic")
    );
    assert!(security.ids_alerts.iter().any(|alert| {
        alert.signature == "Direct external DNS resolver use"
            && alert.severity == packrat_tui::net::security::Severity::Low
    }));
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
            && alert.severity == packrat_tui::net::security::Severity::Critical
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
