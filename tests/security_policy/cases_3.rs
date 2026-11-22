use super::*;
use packrat_tui::engine::AnalysisCore;
use packrat_tui::net::parser::parse_ethernet;

#[test]
fn syn_spike_evidence_excludes_retransmissions_and_other_vlan_scopes() {
    let mut core = AnalysisCore::default();
    for no in 1..=140 {
        let mut packet = tcp_probe(no, [10, 0, 0, 5], 443, 0x02, no as f64 / 1000.0);
        packet.bytes[38..42].copy_from_slice(&42_u32.to_be_bytes());
        packet.vlan_id = Some(10);
        core.analyze(&packet);
    }
    assert!(!core.alert_center.items.iter().any(|alert| alert.title == "SYN arrival spike"));

    for no in 141..=200 {
        let mut packet = tcp_probe(no, [10, 0, 0, 5], 443, 0x02, no as f64 / 1000.0);
        packet.vlan_id = Some(10);
        core.analyze(&packet);
        packet.vlan_id = Some(20);
        packet.no += 1000;
        core.analyze(&packet);
    }
    assert!(!core.alert_center.items.iter().any(|alert| alert.title == "SYN arrival spike"));

    for no in 201..=239 {
        let mut packet = tcp_probe(no, [10, 0, 0, 5], 443, 0x02, no as f64 / 1000.0);
        packet.vlan_id = Some(10);
        core.analyze(&packet);
    }
    let spikes: Vec<_> = core.alert_center.items.iter()
        .filter(|alert| alert.title == "SYN arrival spike").collect();
    assert_eq!(spikes.len(), 1);
    assert_eq!(spikes[0].packet_refs, std::iter::once(1).chain(141..=239).collect::<Vec<_>>());
    assert_eq!(spikes[0].provenance.as_ref().unwrap().rule_id, "tcp.syn_arrival_spike");
    assert_eq!(spikes[0].severity, "HIGH");
    assert!(spikes[0].detail.contains("service impact is unverified"));
    assert!(core.incidents.incidents.is_empty());
}

pub(super) fn ipv6_frame(target: u16, next_header: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 54];
    bytes[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
    bytes[14] = 0x60;
    bytes[18..20].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes[20] = next_header;
    bytes[21] = 64;
    bytes[22..38].copy_from_slice(&"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
    bytes[38..54].copy_from_slice(&"2001:db8:1::".parse::<std::net::Ipv6Addr>().unwrap().octets());
    bytes[52..54].copy_from_slice(&target.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn analyze_ipv6(core: &mut AnalysisCore, no: u64, bytes: &[u8]) {
    core.analyze(&parse_ethernet(bytes, no, no as f64 / 1000.0));
}

#[test]
fn wpad_finding_requires_a_complete_nbns_address_reply() {
    let mut core = AnalysisCore::default();
    let frame = |no, source: u16, dest: u16, payload: &[u8]| {
        let mut raw = vec![0; 42];
        raw[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        raw[14] = 0x45;
        raw[16..18].copy_from_slice(&(28 + payload.len() as u16).to_be_bytes());
        raw[23] = 17;
        raw[26..34].copy_from_slice(&[10, 0, 0, 53, 10, 0, 0, 5]);
        raw[34..36].copy_from_slice(&source.to_be_bytes());
        raw[36..38].copy_from_slice(&dest.to_be_bytes());
        raw[38..40].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
        raw.extend_from_slice(payload);
        parse_ethernet(&raw, no, no as f64)
    };
    let mut reply = vec![0, 42, 0x85, 0, 0, 0, 0, 1, 0, 0, 0, 0, 32];
    for &byte in b"WPAD           \0" {
        reply.extend([b'A' + (byte >> 4), b'A' + (byte & 15)]);
    }
    reply.extend([0, 0, 0x20, 0, 1, 0, 0, 0, 60, 0, 6, 0, 0, 192, 0, 2, 10]);
    let mut query = reply[..46].to_vec();
    query[2..8].copy_from_slice(&[1, 0, 0, 1, 0, 0]);
    query.extend([0, 0x20, 0, 1]);
    let mut other_name = reply.clone();
    other_name[13] = b'A';
    let mut truncated = reply.clone();
    truncated.pop();
    let mut failed = reply.clone();
    failed[3] = 3;
    for input in [
        frame(1, 50_000, 137, &query),
        frame(2, 50_000, 137, b"\0\x20CK"),
        frame(3, 137, 50_000, &other_name),
        frame(4, 137, 50_000, &truncated),
        frame(5, 137, 50_000, &failed),
    ] {
        core.analyze(&input);
    }
    assert!(core.alert_center.items.is_empty());
    core.analyze(&frame(6, 137, 50_000, &reply));
    let alerts = &core.alert_center.items;
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].packet_refs, [6]);
    assert_eq!(alerts[0].provenance.as_ref().unwrap().rule_id, "nbns.wpad_address_reply");
    assert!(alerts[0].detail.contains("192.0.2.10"));
    assert!(alerts[0].detail.contains("client use unverified"));
    assert!(core.incidents.incidents.is_empty());
}

#[rstest]
#[case(false)]
#[case(true)]
fn administrative_fanout_requires_scoped_syn_ack_pairs(#[case] ipv6: bool) {
    let mut core = AnalysisCore::default();
    let make = |no: u64, host: u8, response: bool, ack: u32, vlan: u16| {
        let (sequence, flag, source_port, destination_port) = if response {
            (200_u32, 0x12, 445_u16, 50_000_u16)
        } else {
            (u32::MAX, 0x02, 50_000, 445)
        };
        let mut tcp = [0; 20];
        tcp[..2].copy_from_slice(&source_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&destination_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = flag;
        let raw = if ipv6 {
            let mut raw = ipv6_frame(u16::from(host), 6, &tcp);
            raw[22..24].copy_from_slice(&[0xfd, 0]);
            raw[38..40].copy_from_slice(&[0xfd, 0]);
            if response {
                for i in 22..38 { raw.swap(i, i + 16); }
            }
            raw
        } else {
            let mut raw = ipv4_tcp_packet(no, sequence, flag, &[]).bytes;
            let (client, server) = ([10, 0, 0, 9], [10, 0, 1, host]);
            let (source, destination) = if response { (server, client) } else { (client, server) };
            raw[26..30].copy_from_slice(&source);
            raw[30..34].copy_from_slice(&destination);
            raw[34..54].copy_from_slice(&tcp);
            raw
        };
        let mut packet = parse_ethernet(&raw, no, no as f64 / 100.0);
        packet.vlan_id = Some(vlan);
        packet
    };
    const TITLE: &str = "Administrative service response fan-out";
    for host in 1..=8 {
        core.analyze(&make(u64::from(host), host, false, 0, 10));
    }
    for host in 1..=8 {
        let base = 8 + u64::from(host) * 3;
        core.analyze(&make(base, host, true, 1, 10));
        core.analyze(&make(base + 1, host, true, 0, 20));
        if host < 8 {
            core.analyze(&make(base + 2, host, true, 0, 10));
        }
    }
    core.analyze(&make(34, 1, true, 0, 10));
    assert!(core.alert_center.items.iter().all(|alert| alert.title != TITLE));

    core.analyze(&make(35, 8, true, 0, 10));
    let alert = core.alert_center.items.iter().find(|alert| alert.title == TITLE).unwrap();
    assert_eq!(alert.packet_refs, [1, 13, 2, 16, 3, 19, 4, 22, 5, 25, 6, 28, 7, 31, 8, 35]);
    assert_eq!(alert.severity, "MEDIUM");
    assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "tcp.admin_service_response_fanout");
    assert!(alert.detail.contains("login outcomes unverified"));

    let mut frame = 36;
    let mut pair = |core: &mut AnalysisCore, host, timestamp| {
        for response in [false, true] {
            let mut packet = make(frame, host, response, 0, 10);
            packet.timestamp = timestamp;
            core.analyze(&packet);
            frame += 1;
        }
    };
    for host in 1..=6 {
        pair(&mut core, host, 58.0);
    }
    for host in 9..=10 {
        pair(&mut core, host, 61.0);
    }
    assert_eq!(core.alert_center.items.iter().filter(|alert| alert.title == TITLE).count(), 1);

    pair(&mut core, 1, 116.0);
    for host in 21..=27 {
        pair(&mut core, host, 122.0);
    }
    let bursts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == TITLE).collect();
    assert_eq!(bursts.len(), 2);
    assert_ne!(bursts[0].id, bursts[1].id);
    let mut episode_frames = bursts[1].packet_refs.clone();
    episode_frames.sort_unstable();
    assert_eq!(episode_frames, (52..68).collect::<Vec<_>>());
}

#[rstest]
#[case(false)]
#[case(true)]
fn ssh_burst_counts_unique_connection_starts_and_keeps_scopes_separate(#[case] ipv6: bool) {
    let mut core = AnalysisCore::default();
    let make_packet = |no: u64, sequence: u32, flags: u8, vlan: u16| {
        let mut packet = if ipv6 {
            let mut tcp = [0; 20];
            tcp[..2].copy_from_slice(&50000_u16.to_be_bytes());
            tcp[2..4].copy_from_slice(&22_u16.to_be_bytes());
            tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
            tcp[12] = 0x50;
            tcp[13] = flags;
            parse_ethernet(&ipv6_frame(5, 6, &tcp), no, no as f64 / 100.0)
        } else {
            let mut packet = tcp_probe(no, [10, 0, 0, 5], 22, flags, no as f64 / 100.0);
            packet.bytes[38..42].copy_from_slice(&sequence.to_be_bytes());
            packet
        };
        packet.vlan_id = Some(vlan);
        packet
    };
    for no in 1..=5 {
        core.analyze(&make_packet(no, no as u32, 0x18, 10));
        core.analyze(&make_packet(no + 5, no as u32, 0x12, 10));
        core.analyze(&make_packet(no + 10, 100, 0x02, 10));
    }
    for no in 16..=23 {
        core.analyze(&make_packet(no, no as u32, 0x02, if no % 2 == 0 { 20 } else { 30 }));
    }
    assert!(core.alert_center.items.iter().all(|a| a.source != "AUTH"));

    core.analyze(&make_packet(24, 24, 0x02, 20));
    core.analyze(&make_packet(25, 25, 0x02, 30));
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|a| a.source == "AUTH").collect();
    assert_eq!(alerts.len(), 2);
    for (ending, refs) in [(24, [16, 18, 20, 22, 24]), (25, [17, 19, 21, 23, 25])] {
        let alert = alerts.iter().find(|a| a.last_packet == ending).unwrap();
        assert_eq!(alert.title, "SSH connection-start burst");
        assert_eq!(alert.severity, "MEDIUM");
        assert_eq!(alert.packet_refs, refs);
        assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "ssh.connection_start_burst");
        assert!(alert.detail.contains("authentication outcome not observable"));
    }
    assert!(core.incidents.incidents.is_empty());
}

pub(super) fn smb2_session_setup_reply(status: u32, flags: u8) -> Vec<u8> {
    let mut payload = vec![0; 4 + 73];
    payload[3] = 73;
    let message = &mut payload[4..];
    message[..6].copy_from_slice(b"\xfeSMB\x40\x00");
    message[8..12].copy_from_slice(&status.to_le_bytes());
    message[12..14].copy_from_slice(&1_u16.to_le_bytes());
    message[16] = flags;
    message[64..66].copy_from_slice(&9_u16.to_le_bytes());
    payload
}

#[test]
fn legacy_smb_alert_requires_a_complete_successful_server_reply() {
    let mut core = AnalysisCore::default();
    let make_reply = |no, payload: &[u8]| {
        let mut packet = ipv4_tcp_packet(no, no as u32 * 1024, 0x18, payload);
        packet.bytes[34..36].copy_from_slice(&445_u16.to_be_bytes());
        packet.bytes[36..38].copy_from_slice(&50_000_u16.to_be_bytes());
        packet.src_port = Some(445);
        packet.dst_port = Some(50_000);
        packet.protocol = "SMB".into();
        packet
    };
    let mut echo = vec![0; 4 + 41];
    echo[3] = 41;
    let message = &mut echo[4..];
    message[..4].copy_from_slice(b"\xffSMB");
    message[4] = 0x2b;
    message[9] = 0x80;
    message[32..37].copy_from_slice(&[1, 1, 0, 4, 0]);
    message[37..].copy_from_slice(b"ping");
    let mut negotiate = echo.clone();
    negotiate[8] = 0x72;
    let mut failed = echo.clone();
    failed[9] = 1;
    let mut request = echo.clone();
    request[13] = 0;
    let mut truncated = echo.clone();
    truncated.pop();
    let mut malformed = echo.clone();
    malformed[39] = 32;
    let modern = smb2_session_setup_reply(0, 1);
    for (index, payload) in [
        &negotiate, &failed, &request, &truncated, &malformed, &modern,
    ].into_iter().enumerate() {
        core.analyze(&make_reply(index as u64 + 1, payload));
    }
    assert!(core.alert_center.items.is_empty());

    core.analyze(&make_reply(7, &echo));
    let alert = core.alert_center.items.iter().find(|a| a.title == "SMBv1 server response").unwrap();
    assert_eq!(alert.severity, "MEDIUM");
    assert_eq!(alert.packet_refs, [7]);
    assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "smb1.successful_server_response");
    assert!(alert.detail.contains("exploitation status unverified"));
    assert!(core.incidents.incidents.is_empty());
}

#[test]
fn ordinary_protocol_headers_and_text_do_not_open_cve_incidents() {
    let mut core = AnalysisCore::default();
    let mut tpkt = vec![0; 112];
    tpkt[..4].copy_from_slice(&[3, 0, 0, 112]);
    for (no, port, payload) in [
        (1, 3389_u16, tpkt.as_slice()),
        (2, 445, b"Service label SMBr"),
        (3, 135, b"\x1c\x00SpoolSS status"),
    ] {
        let mut packet = ipv4_tcp_packet(no, 100, 0x18, payload);
        packet.bytes[36..38].copy_from_slice(&port.to_be_bytes());
        packet.dst_port = Some(port);
        core.analyze(&packet);
    }
    assert!(core.incidents.incidents.is_empty());
    assert!(core.alert_center.items.iter().all(|a| a.severity != "CRITICAL"));
}

fn smb2_ntlm_request(message_type: u8) -> Vec<u8> {
    let mut request = vec![0; 4 + 88 + 64];
    request[3] = 88 + 64;
    let message = &mut request[4..];
    message[..6].copy_from_slice(b"\xfeSMB\x40\x00");
    message[12] = 1;
    message[64] = 25;
    message[76] = 88;
    message[78] = 64;
    message[88..96].copy_from_slice(b"NTLMSSP\0");
    message[96] = message_type;
    request
}

#[test]
fn ntlm_fanout_requires_smb2_authenticate_and_retains_scoped_evidence() {
    let mut core = AnalysisCore::default();
    let packet = |no: u64, target: u8, vlan: u16, payload: &[u8]| {
        let mut frame = ipv4_tcp_packet(no, no as u32 * 1024, 0x18, payload);
        frame.protocol = "SMB".into();
        frame.src = "10.0.0.9".into();
        frame.dst = format!("10.0.2.{target}");
        frame.bytes[26..34].copy_from_slice(&[10, 0, 0, 9, 10, 0, 2, target]);
        frame.bytes[36..38].copy_from_slice(&445_u16.to_be_bytes());
        frame.dst_port = Some(445);
        frame.vlan_id = Some(vlan);
        frame
    };
    let negotiate = smb2_ntlm_request(1);
    let authenticate = smb2_ntlm_request(3);
    let mut outside_security_buffer = authenticate.clone();
    outside_security_buffer[4 + 78] = 0;
    let mut incomplete = authenticate.clone();
    incomplete.pop();
    let mut invalid_fields = authenticate.clone();
    invalid_fields[4 + 88 + 12] = 8; // A nonempty response with an invalid offset.
    for (batch, payload) in [
        b"NTLMSSP\0".as_slice(), &negotiate, &outside_security_buffer, &incomplete, &invalid_fields,
    ].into_iter().enumerate() {
        for target in 1..=3 {
            core.analyze(&packet(batch as u64 * 3 + u64::from(target), target, 10, payload));
        }
    }
    for (no, target, vlan) in [(16, 1, 10), (17, 1, 10), (18, 2, 10), (19, 3, 20)] {
        core.analyze(&packet(no, target, vlan, &authenticate));
    }
    assert!(core.alert_center.items.iter().all(|a| {
        a.title != "NTLM authentication fan-out" && !a.title.contains("Pass-the-Hash")
    }));

    core.analyze(&packet(20, 3, 10, &authenticate));
    let alert = core.alert_center.items.iter().find(|a| a.title == "NTLM authentication fan-out").unwrap();
    assert_eq!(alert.packet_refs, [17, 18, 20]);
    assert_eq!(alert.severity, "MEDIUM");
    assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "smb2.ntlm_authentication_fanout");
    assert!(alert.detail.contains("outcomes unverified"));
    assert!(core.incidents.incidents.is_empty(), "{:?}", core.incidents.incidents);
}

#[rstest]
#[case(21, "ftp.not_logged_in_burst")]
#[case(445, "smb2.logon_failure_burst")]
fn logon_reply_bursts_require_complete_server_evidence(#[case] port: u16, #[case] rule_id: &str) {
    let mut core = AnalysisCore::default();
    let mut track = |no, sequence, from_server, payload: &[u8]| {
        let mut packet = ipv4_tcp_packet(no, sequence, 0x18, payload);
        let (source, destination) = if from_server { (port, 50_000_u16) } else { (50_000, port) };
        packet.bytes[34..36].copy_from_slice(&source.to_be_bytes());
        packet.bytes[36..38].copy_from_slice(&destination.to_be_bytes());
        packet.src_port = Some(source);
        packet.dst_port = Some(destination);
        core.analyze(&packet);
    };
    let (valid, ignored) = if port == 21 {
        (
            b"530 Please log in first\r\n".to_vec(),
            vec![b"200 530 Login incorrect\r\n".to_vec(), b"530 Login incorrect".to_vec()],
        )
    } else {
        let valid = smb2_session_setup_reply(0xc000_006d, 1);
        let mut incomplete = valid.clone();
        incomplete.pop();
        (
            valid,
            vec![
                smb2_session_setup_reply(0xc000_0016, 1),
                smb2_session_setup_reply(0xc000_006d, 0),
                incomplete,
                b"NTLMSSP\0".to_vec(),
            ],
        )
    };
    for no in 1..=5 {
        track(no, no as u32, false, &valid);
    }
    for (index, payload) in ignored.iter().enumerate() {
        for i in 0..5 {
            let no = 6 + (index as u64 * 5) + i;
            track(no, no as u32, true, payload);
        }
    }
    for (no, sequence) in [(26, 100), (27, 100), (28, 101), (29, 102), (30, 103), (31, 104)] {
        track(no, sequence, true, &valid);
    }
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|a| a.source == "AUTH").collect();
    assert_eq!(alerts.len(), 1);
    let alert = alerts[0];
    assert_eq!(alert.severity, "MEDIUM");
    assert_eq!(alert.provenance.as_ref().unwrap().rule_id, rule_id);
    assert_eq!(alert.packet_refs, [26, 28, 29, 30, 31]);
    assert!(alert.detail.contains(&format!("client 10.0.0.5 and service 203.0.113.9:{port}")));
}

#[test]
fn ipv6_tcp_scan_counts_only_complete_initial_syns_through_extensions() {
    let mut core = AnalysisCore::default();
    let mut tcp = [0; 24];
    tcp[..2].copy_from_slice(&40000_u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&443_u16.to_be_bytes());
    tcp[12] = 0x50;
    for target in 1..=12 {
        let no = u64::from(target);
        tcp[13] = 0x12;
        analyze_ipv6(&mut core, no, &ipv6_frame(target, 6, &tcp));
        tcp[13] = 0x02;
        let mut fragment = vec![6, 0, 0, 1, 0, 0, 0, 1];
        fragment.extend_from_slice(&tcp);
        analyze_ipv6(&mut core, no + 12, &ipv6_frame(target, 44, &fragment));
        let mut truncated = ipv6_frame(target, 6, &tcp);
        truncated.pop();
        analyze_ipv6(&mut core, no + 24, &truncated);
    }
    assert!(!core.alert_center.items.iter().any(|a| a.title == "Horizontal host scan"));

    let mut options = vec![6, 0, 0, 0, 0, 0, 0, 0];
    options.extend_from_slice(&tcp);
    for target in 1..=12 {
        analyze_ipv6(&mut core, u64::from(target) + 36, &ipv6_frame(target, 60, &options));
    }
    let alert = core.alert_center.items.iter().find(|a| a.title == "Horizontal host scan").unwrap();
    assert_eq!(alert.packet_refs, (37..=48).collect::<Vec<_>>());
    assert_eq!(alert.provenance.as_ref().unwrap().revision, 7);
}

#[rstest]
#[case(17, [0x9c, 0x40, 0x01, 0xbb, 0, 7, 0, 0], [0x9c, 0x40, 0x01, 0xbb, 0, 8, 0, 0], "Horizontal host scan", "scan.horizontal")]
#[case(58, [129, 0, 0, 0, 0, 0, 0, 0], [128, 0, 0, 0, 0, 0, 0, 0], "ICMP address sweep", "icmp.address_sweep")]
fn ipv6_udp_and_echo_sweeps_keep_only_distinct_matching_evidence(
    #[case] next_header: u8,
    #[case] ignored: [u8; 8],
    #[case] counted: [u8; 8],
    #[case] title: &str,
    #[case] rule_id: &str,
) {
    let mut core = AnalysisCore::default();
    for no in 1..=12 {
        analyze_ipv6(&mut core, no, &ipv6_frame(no as u16, next_header, &ignored));
        analyze_ipv6(&mut core, no + 12, &ipv6_frame(1, next_header, &counted));
    }
    assert!(!core.alert_center.items.iter().any(|a| a.title == title));

    for target in 2..=12 {
        analyze_ipv6(&mut core, u64::from(target) + 23, &ipv6_frame(target, next_header, &counted));
    }
    let alert = core.alert_center.items.iter().find(|a| a.title == title).unwrap();
    assert_eq!(alert.packet_refs, (24..=35).collect::<Vec<_>>());
    assert_eq!(alert.provenance.as_ref().unwrap().rule_id, rule_id);
}
