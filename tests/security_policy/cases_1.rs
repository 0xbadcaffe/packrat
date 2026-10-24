use super::*;

#[rstest]
#[case("EternalBlue")]
#[case("BlueKeep (CVE-2019-0708)")]
#[case("Log4Shell (CVE-2021-44228)")]
#[case("Shellcode NOP sled")]
#[case("LLMNR Poisoning")]
#[case("NBNS WPAD Poisoning")]
#[case("Directory Traversal")]
#[case("SQL Injection Probe")]
#[case("XSS Probe")]
#[case("Heartbleed (CVE-2014-0160)")]
#[case("PrintNightmare (CVE-2021-1675)")]
#[case("Pass-the-Hash (suspected)")]
#[case("Log4Shell via DNS (CVE-2021-44228)")]
fn shipped_signature_replays(#[case] signature: &str) {
    let mut security = SecurityEngine::default();
    security.update(&fixture(signature));
    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == signature),
        "fixture did not trigger {signature}; got {:?}",
        security
            .ids_alerts
            .iter()
            .map(|alert| alert.signature)
            .collect::<Vec<_>>(),
    );
}

#[test]
fn payload_signatures_are_ascii_case_insensitive() {
    let mut security = SecurityEngine::default();
    security.update(&packet(
        "HTTP",
        8080,
        "",
        b"prefix ${JnDi:ldap://example.test/x} suffix".to_vec(),
    ));
    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| { alert.signature == "Log4Shell (CVE-2021-44228)" })
    );
}

#[test]
fn benign_baseline_triggers_no_catalogued_detectors() {
    let mut security = SecurityEngine::default();
    security.update(&packet(
        "HTTP",
        80,
        "GET / HTTP/1.1",
        b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(),
    ));
    assert!(security.ids_alerts.is_empty());
}

#[test]
fn vlan_replay_detects_double_tag_native_pcp_and_dtp() {
    let mut intel = VlanIntel::default();

    let mut qinq = ethernet_packet(
        1,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
        [0, 1, 2, 3, 4, 5],
        Some(20),
    );
    qinq.outer_vlan_id = Some(100);
    intel.ingest(&qinq);

    let native = ethernet_packet(
        2,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02],
        [0, 1, 2, 3, 4, 5],
        Some(1),
    );
    intel.ingest(&native);

    let mut pcp = ethernet_packet(
        3,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03],
        [0, 1, 2, 3, 4, 5],
        Some(30),
    );
    pcp.vlan_pcp = Some(7);
    intel.ingest(&pcp);

    let dtp = ethernet_packet(
        4,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x04],
        [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc],
        None,
    );
    intel.ingest(&dtp);

    assert!(
        intel
            .alerts
            .iter()
            .any(|alert| alert.category == "VLAN-Hop" && alert.severity == AlertSeverity::Critical)
    );
    assert!(
        intel
            .alerts
            .iter()
            .any(|alert| alert.category == "Native-VLAN")
    );
    assert!(
        intel
            .alerts
            .iter()
            .any(|alert| alert.category == "PCP-Abuse")
    );
    assert!(
        intel
            .alerts
            .iter()
            .any(|alert| alert.category == "DTP" && alert.severity == AlertSeverity::Critical)
    );
}

#[test]
fn vlan_replay_detects_mac_crossing_vlans() {
    let mut intel = VlanIntel::default();
    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x05];
    intel.ingest(&ethernet_packet(1, mac, [0, 1, 2, 3, 4, 5], Some(10)));
    intel.ingest(&ethernet_packet(2, mac, [0, 1, 2, 3, 4, 5], Some(20)));

    assert!(
        intel
            .alerts
            .iter()
            .any(|alert| alert.category == "MAC-VLAN-Cross")
    );
}

#[test]
fn detects_conflicting_ipv4_fragment_overlap() {
    let mut security = SecurityEngine::default();
    security.update(&ipv4_fragment_packet(
        1,
        0x1234,
        0,
        true,
        b"abcdefghijklmnop",
    ));
    security.update(&ipv4_fragment_packet(2, 0x1234, 8, false, b"XXXXXXXX"));

    assert!(security.ids_alerts.iter().any(|alert| {
        alert.signature == "Conflicting IPv4 fragments"
            && alert.severity == packrat_tui::net::security::Severity::Critical
    }));
}

#[test]
fn identical_ipv4_fragment_retransmission_is_not_an_overlap_alert() {
    let mut security = SecurityEngine::default();
    let fragment = ipv4_fragment_packet(1, 0x2345, 0, true, b"abcdefgh");
    security.update(&fragment);
    security.update(&fragment.with_number_and_timestamp(2, 2.0));

    assert!(
        !security
            .ids_alerts
            .iter()
            .any(|alert| { alert.signature == "Conflicting IPv4 fragments" })
    );
}

#[test]
fn detects_tiny_and_excessive_ipv4_fragments() {
    let mut security = SecurityEngine::default();
    security.update(&ipv4_fragment_packet(1, 0x3456, 0, true, b"tiny"));
    for no in 2..=66 {
        security.update(&ipv4_fragment_packet(no, 0x4567, 0, true, b"12345678"));
    }

    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "Tiny IPv4 fragment")
    );
    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "IPv4 fragment flood")
    );
}

#[test]
fn detects_malformed_ipv4_fragment_length() {
    let mut malformed = ipv4_fragment_packet(1, 0x5678, 0, true, b"12345678");
    malformed.bytes[16..18].copy_from_slice(&10_u16.to_be_bytes());
    let mut security = SecurityEngine::default();
    security.update(&malformed);
    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "Malformed IPv4 fragment")
    );
}

#[test]
fn detects_conflicting_tcp_retransmission_but_allows_identical_retransmission() {
    let mut security = SecurityEngine::default();
    security.update(&ipv4_tcp_packet(1, 100, 0x18, b"original"));
    security.update(&ipv4_tcp_packet(2, 100, 0x18, b"original"));
    assert!(
        !security
            .ids_alerts
            .iter()
            .any(|alert| { alert.signature == "Conflicting TCP retransmission" })
    );

    security.update(&ipv4_tcp_packet(3, 104, 0x18, b"CHANGED"));
    assert!(security.ids_alerts.iter().any(|alert| {
        alert.signature == "Conflicting TCP retransmission"
            && alert.severity == packrat_tui::net::security::Severity::Critical
    }));
}

#[test]
fn detects_illegal_and_malformed_tcp_headers() {
    let mut security = SecurityEngine::default();
    security.update(&ipv4_tcp_packet(1, 100, 0x03, b""));

    let mut malformed = ipv4_tcp_packet(2, 100, 0x10, b"");
    malformed.bytes[46] = 0x40;
    security.update(&malformed);

    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "Illegal TCP flag combination")
    );
    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "Malformed TCP header")
    );
}

#[test]
fn detects_tcp_payload_continuing_after_reset() {
    let mut security = SecurityEngine::default();
    security.update(&ipv4_tcp_packet(1, 100, 0x04, b""));
    security.update(&ipv4_tcp_packet(2, 101, 0x18, b"unexpected"));

    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "TCP payload after reset")
    );
}

#[test]
fn detects_vertical_and_horizontal_scan_windows() {
    let mut vertical = SecurityEngine::default();
    for index in 0..12_u16 {
        vertical.update(&tcp_probe(
            index as u64 + 1,
            [10, 0, 0, 5],
            1000 + index,
            0x02,
            index as f64,
        ));
    }
    assert!(
        vertical
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "Vertical port scan")
    );

    let mut horizontal = SecurityEngine::default();
    for index in 1..=12_u8 {
        horizontal.update(&tcp_probe(
            index as u64,
            [10, 0, 0, index],
            445,
            0x02,
            index as f64,
        ));
    }
    assert!(
        horizontal
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "Horizontal host scan")
    );
}

#[test]
fn detects_tcp_stealth_scan_flag_patterns() {
    let mut security = SecurityEngine::default();
    security.update(&tcp_probe(1, [10, 0, 0, 5], 80, 0x00, 1.0));
    security.update(&tcp_probe(2, [10, 0, 0, 5], 80, 0x01, 2.0));
    security.update(&tcp_probe(3, [10, 0, 0, 5], 80, 0x29, 3.0));

    let count = security
        .ids_alerts
        .iter()
        .filter(|alert| alert.signature == "TCP stealth scan probe")
        .count();
    assert_eq!(count, 3);
}

#[test]
fn detects_syn_flood_within_one_second() {
    let mut security = SecurityEngine::default();
    for index in 0..100_u64 {
        security.update(&tcp_probe(
            index + 1,
            [10, 0, 0, 5],
            443,
            0x02,
            index as f64 / 1000.0,
        ));
    }

    assert!(security.ids_alerts.iter().any(|alert| {
        alert.signature == "SYN flood"
            && alert.severity == packrat_tui::net::security::Severity::Critical
    }));
}

#[test]
fn detects_icmp_address_sweep() {
    let mut security = SecurityEngine::default();
    for index in 1..=12_u8 {
        let mut echo = packet("ICMP", 0, "Echo request", vec![]);
        echo.no = index as u64;
        echo.timestamp = index as f64;
        echo.dst = format!("10.0.0.{index}");
        echo.dst_port = None;
        security.update(&echo);
    }

    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "ICMP address sweep")
    );
}

#[test]
fn detects_invalid_ipv6_neighbor_discovery_and_binding_change() {
    let target = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
    let source = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut security = SecurityEngine::default();
    security.update(&ipv6_control_packet(
        1,
        [0, 1, 2, 3, 4, 5],
        source,
        64,
        &neighbor_advertisement(target, [0, 1, 2, 3, 4, 5]),
    ));
    security.update(&ipv6_control_packet(
        2,
        [0, 1, 2, 3, 4, 6],
        source,
        255,
        &neighbor_advertisement(target, [0, 1, 2, 3, 4, 6]),
    ));

    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "Invalid IPv6 neighbor discovery hop limit")
    );
    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "IPv6 neighbor binding changed")
    );
}

#[test]
fn detects_invalid_and_flooded_router_advertisements() {
    let global_source = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut ra = vec![0_u8; 16];
    ra[0] = 134;
    let mut security = SecurityEngine::default();
    for index in 0..20_u64 {
        let mut packet =
            ipv6_control_packet(index + 1, [0, 1, 2, 3, 4, 5], global_source, 255, &ra);
        packet.timestamp = index as f64 / 1000.0;
        security.update(&packet);
    }

    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "Invalid IPv6 router advertisement source")
    );
    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "IPv6 router advertisement flood")
    );
}

#[test]
fn detects_excessive_ipv6_extension_header_chain() {
    let source = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut extensions = vec![0_u8; 9 * 8 + 8];
    for index in 0..9 {
        extensions[index * 8] = if index == 8 { 58 } else { 0 };
    }
    extensions[9 * 8] = 128;
    let mut packet = ipv6_control_packet(1, [0, 1, 2, 3, 4, 5], source, 255, &extensions);
    packet.bytes[20] = 0;

    let mut security = SecurityEngine::default();
    security.update(&packet);
    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "Excessive IPv6 extension headers")
    );
}
