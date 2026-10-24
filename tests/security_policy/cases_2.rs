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
fn detects_periodic_fixed_size_command_and_control_beacon() {
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
            .any(|alert| { alert.signature == "Periodic command-and-control beacon" })
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
            .any(|alert| { alert.signature == "Periodic command-and-control beacon" })
    );
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
fn detects_administrative_and_ntlm_lateral_fanout() {
    let mut security = SecurityEngine::default();
    for index in 1..=8_u8 {
        let mut smb = packet("SMB", 445, "", vec![0; 64]);
        smb.no = index as u64;
        smb.timestamp = index as f64;
        smb.src = "10.0.0.5".into();
        smb.dst = format!("10.0.1.{index}");
        security.update(&smb);
    }
    for index in 1..=3_u8 {
        let mut ntlm = packet("SMB", 445, "", b"NTLMSSP authentication".to_vec());
        ntlm.no = 20 + index as u64;
        ntlm.timestamp = 20.0 + index as f64;
        ntlm.src = "10.0.0.9".into();
        ntlm.dst = format!("10.0.2.{index}");
        security.update(&ntlm);
    }

    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "Administrative service fan-out")
    );
    assert!(
        security
            .ids_alerts
            .iter()
            .any(|alert| alert.signature == "NTLM authentication fan-out")
    );
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
