use super::*;
use packrat_tui::analysis::alert_center::AlertDisposition;
use packrat_tui::engine::AnalysisCore;

#[rstest::rstest]
#[case(80, "http.unauthorized_burst")]
#[case(21, "ftp.not_logged_in_burst")]
#[case(445, "smb2.logon_failure_burst")]
fn authentication_reply_bursts_require_tcp_data_with_ack(
    #[case] server_port: u16,
    #[case] rule: &str,
) {
    let payload = match server_port {
        80 => b"HTTP/1.1 401 Unauthorized\r\n\r\n".to_vec(),
        21 => b"530 Not logged in\r\n".to_vec(),
        445 => cases_3::smb2_session_setup_reply(0xc000_006d, 1),
        _ => unreachable!(),
    };
    let make = |no: u64, flags| {
        let mut packet = ipv4_tcp_packet(no, no as u32 * 1024, flags, &payload);
        packet.bytes[34..36].copy_from_slice(&server_port.to_be_bytes());
        packet.bytes[36..38].copy_from_slice(&50_000_u16.to_be_bytes());
        packet.src_port = Some(server_port);
        packet.dst_port = Some(50_000);
        packet
    };
    let mut core = AnalysisCore::default();
    for (no, flags) in [0x04, 0x14, 0x02, 0x12, 0x08].into_iter().enumerate() {
        core.analyze(&make(no as u64 + 1, flags));
    }
    assert!(core.alert_center.items.iter().all(|alert| alert.source != "AUTH"));

    for no in 6..=10 {
        core.analyze(&make(no, if no == 10 { 0x19 } else { 0x18 }));
    }
    let alert = core.alert_center.items.iter().find(|alert| alert.source == "AUTH").unwrap();
    assert_eq!(alert.provenance.as_ref().unwrap().rule_id, rule);
    assert_eq!(alert.packet_refs, [6, 7, 8, 9, 10]);
    let flow = alert.flow.expect("validated trigger tuple");
    assert_eq!((flow.source.port(), flow.destination.port()), (server_port, 50_000));
    let (old_id, scope) = (alert.id, alert.capture_id.clone());
    assert!(core.alert_center.set_disposition(old_id, scope.as_deref(), AlertDisposition::Benign));
    for (no, original) in (46..=50).zip(6..=10) {
        let mut duplicate = make(original, 0x18);
        duplicate.no = no;
        duplicate.timestamp = no as f64;
        core.analyze(&duplicate);
    }
    assert_eq!(core.alert_center.items.iter().filter(|alert| alert.source == "AUTH").count(), 1);
    for no in 51..=55 {
        core.analyze(&make(no, 0x18));
    }
    let episodes: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.source == "AUTH").collect();
    assert_eq!(episodes.len(), 2);
    assert_eq!(episodes[0].disposition, AlertDisposition::Benign);
    assert_eq!(episodes[0].packet_refs, [6, 7, 8, 9, 10]);
    assert_ne!(episodes[1].id, old_id);
    assert_eq!(episodes[1].disposition, AlertDisposition::New);
    assert_eq!(episodes[1].packet_refs, [51, 52, 53, 54, 55]);
}

#[rstest::rstest]
#[case(80, "http.unauthorized_burst", 17)]
#[case(21, "ftp.not_logged_in_burst", 7)]
#[case(445, "smb2.logon_failure_burst", 7)]
#[case(22, "ssh.connection_start_burst", 6)]
fn authentication_bursts_are_separate_on_same_id_different_tag_paths(
    #[case] port: u16,
    #[case] rule: &str,
    #[case] revision: u16,
) {
    use packrat_tui::net::parser::parse_ethernet;

    let payload = match port {
        80 => b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n".to_vec(),
        21 => b"530 Not logged in\r\n".to_vec(),
        445 => cases_3::smb2_session_setup_reply(0xc000_006d, 1),
        22 => Vec::new(),
        _ => unreachable!(),
    };
    let mut core = AnalysisCore::default();
    for no in 1..=10_u64 {
        let secondary_path = no % 2 == 0;
        let sequence = no.div_ceil(2) as u32 * 1024;
        let mut raw = ipv4_tcp_packet(no, sequence, if port == 22 { 0x02 } else { 0x18 }, &payload).bytes;
        let (source, destination) = if port == 22 { (50_000_u16, port) } else { (port, 50_000_u16) };
        raw[34..36].copy_from_slice(&source.to_be_bytes());
        raw[36..38].copy_from_slice(&destination.to_be_bytes());
        let tpid = if secondary_path { 0x88a8_u16 } else { 0x8100_u16 };
        let tci = if no % 4 < 2 { 20_u16 } else { 0xb014_u16 };
        raw.splice(12..12, [tpid, tci].into_iter().flat_map(u16::to_be_bytes));
        core.analyze(&parse_ethernet(&raw, no, no as f64));
        if no < 9 {
            assert!(core.alert_center.items.iter().all(|alert| alert.source != "AUTH"));
        }
    }
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.source == "AUTH").collect();
    assert_eq!(alerts.len(), 2);
    for (alert, frames) in alerts.into_iter().zip([[1, 3, 5, 7, 9], [2, 4, 6, 8, 10]]) {
        let provenance = alert.provenance.as_ref().unwrap();
        assert_eq!(provenance.rule_id, rule);
        assert_eq!(provenance.revision, revision);
        assert_eq!(alert.packet_refs, frames);
    }
}

#[cfg(feature = "terminal-ui")]
#[rstest::rstest]
#[case(21, "ftp.not_logged_in_burst")]
#[case(22, "ssh.connection_start_burst")]
#[case(445, "smb2.logon_failure_burst")]
fn opted_in_transport_auth_samples_survive_history_rollover(
    #[case] port: u16,
    #[case] rule: &str,
) {
    use super::archive_fixture::{finish, roll_history, start};
    use packrat_tui::net::parser::parse_ethernet;
    use packrat_tui::storage::packet_archive::PacketArchive;

    let payload = match port {
        21 => b"530 Not logged in\r\n".to_vec(),
        22 => Vec::new(),
        445 => cases_3::smb2_session_setup_reply(0xc000_006d, 1),
        _ => unreachable!(),
    };
    let (flags, source_port, destination_port) = if port == 22 {
        (0x02, 50_000_u16, port)
    } else {
        (0x18, port, 50_000_u16)
    };
    let make = |frame, time, token, vlan| {
        let mut bytes = ipv4_tcp_packet(frame, token, flags, &payload).bytes;
        bytes[34..36].copy_from_slice(&source_port.to_be_bytes());
        bytes[36..38].copy_from_slice(&destination_port.to_be_bytes());
        bytes.splice(12..12, [0x81, 0, 0, vlan]);
        parse_ethernet(&bytes, frame, time)
    };
    for selected in [false, true] {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("archive");
        let rules = vec![if selected { rule } else { "http.unauthorized_burst" }.into()];
        let mut app = start(&path, rules);
        let mut expected: Vec<_> = (1..=4).map(|frame| make(frame, frame as f64, frame as u32 * 1024, 10)).collect();
        for packet in &expected {
            app.inject_packet(packet.clone());
        }
        app.inject_packet(make(5, 5.0, 6 * 1024, 20));
        app.inject_packet(make(6, 6.0, 4 * 1024, 10));
        let trigger = roll_history(&mut app, 7);
        let last = make(trigger, 3.5, 5 * 1024, 10);
        app.inject_packet(last.clone());
        expected.push(last);
        finish(&mut app);

        let alert = app.query_core(move |core| core.alert_center.items.iter()
            .find(|item| item.provenance.as_ref().is_some_and(|p| p.rule_id == rule)).cloned())
            .unwrap().unwrap();
        assert_eq!(alert.packet_refs, [1, 2, 3, 4, trigger]);
        let flow = alert.flow.expect("validated trigger tuple");
        assert_eq!((flow.source.port(), flow.destination.port()), (source_port, destination_port));
        let scope = alert.capture_id.unwrap();
        let mut archive = PacketArchive::open_readonly(&path).unwrap();
        assert_eq!(archive.count().unwrap(), if selected { 5 } else { 0 });
        for packet in expected {
            let recovered = archive.packet_for_capture(&scope, packet.no).unwrap();
            assert_eq!(recovered.map(|frame| frame.bytes), selected.then_some(packet.bytes));
        }
    }
}

#[test]
fn ntlm_fanout_requires_tcp_data_with_ack_and_matching_wire_endpoints() {
    const TITLE: &str = "NTLM authentication fan-out";
    let payload = cases_3::smb2_ntlm_request(3);
    let make = |no: u64, target: u8, flags: u8, wire_port: u16| {
        let mut packet = ipv4_tcp_packet(no, 100, flags, &payload);
        packet.bytes[26..34].copy_from_slice(&[10, 0, 0, 9, 10, 0, 2, target]);
        packet.bytes[36..38].copy_from_slice(&wire_port.to_be_bytes());
        packet.src = "10.0.0.9".into();
        packet.dst = format!("10.0.2.{target}");
        packet.dst_port = Some(445);
        packet
    };
    let mut engine = SecurityEngine::default();
    for (no, flags, port) in [(1, 0x12, 445), (2, 0x14, 445), (3, 0x08, 445), (4, 0x18, 446)] {
        engine.update(&make(no, no as u8, flags, port));
    }
    let mut invalid_clock = make(5, 5, 0x18, 445);
    invalid_clock.timestamp = f64::NAN;
    engine.update(&invalid_clock);
    let mut other_wire_source = make(5, 20, 0x18, 445);
    other_wire_source.bytes[29] = 8;
    engine.update(&other_wire_source);
    let mut other_wire_destination = make(5, 21, 0x18, 445);
    other_wire_destination.bytes[33] = 22;
    engine.update(&other_wire_destination);
    assert!(engine.ids_alerts.iter().all(|alert| alert.signature != TITLE));
    engine.update(&make(6, 6, 0x18, 445));
    engine.update(&make(7, 7, 0x18, 445));
    assert!(engine.ids_alerts.iter().all(|alert| alert.signature != TITLE));
    let batch = engine.inspect(&make(8, 8, 0x19, 445));
    let finding = batch.ids.iter().find(|finding| finding.alert.signature == TITLE).unwrap();
    assert_eq!(finding.related_packets, [6, 7]);
}

#[test]
fn ntlm_fanout_counts_an_ipv6_destination_once_across_address_spellings() {
    use packrat_tui::net::parser::parse_ethernet;

    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&50_000_u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&445_u16.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x18;
    tcp.extend_from_slice(&cases_3::smb2_ntlm_request(3));
    let make = |frame, host| {
        let mut raw = cases_3::ipv6_frame(host, 6, &tcp);
        raw[22..26].copy_from_slice(&[0xfd, 0, 0, 0]);
        raw[38..42].copy_from_slice(&[0xfd, 0, 0, 0]);
        parse_ethernet(&raw, frame, frame as f64)
    };
    const TITLE: &str = "NTLM authentication fan-out";
    let mut spelled_out = make(2, 1);
    spelled_out.dst = "FD00:0:1:0:0:0:0:1".into();
    let mut engine = SecurityEngine::default();
    for packet in [make(1, 1), spelled_out, make(3, 2)] {
        let findings = engine.inspect(&packet);
        assert!(findings.ids.iter().all(|finding| finding.alert.signature != TITLE));
    }
    let batch = engine.inspect(&make(4, 3));
    let finding = batch.ids.iter().find(|finding| finding.alert.signature == TITLE).unwrap();
    assert_eq!(finding.related_packets, [2, 3]);
}

#[test]
fn ntlm_fanout_does_not_combine_different_vlan_tag_types() {
    use packrat_tui::net::parser::parse_ethernet;

    let mut engine = SecurityEngine::default();
    let payload = cases_3::smb2_ntlm_request(3);
    let make = |frame, host, tpid: u16, tci: u16| {
        let mut raw = ipv4_tcp_packet(frame, 100, 0x18, &payload).bytes;
        raw[26..34].copy_from_slice(&[10, 0, 0, 9, 10, 0, 2, host]);
        raw[36..38].copy_from_slice(&445_u16.to_be_bytes());
        raw.splice(12..12, [tpid, tci].into_iter().flat_map(u16::to_be_bytes));
        parse_ethernet(&raw, frame, frame as f64)
    };
    const TITLE: &str = "NTLM authentication fan-out";
    for (frame, host, tpid, tci) in [(1, 1, 0x8100, 20), (2, 2, 0x88a8, 20), (3, 3, 0x8100, 20)] {
        let findings = engine.inspect(&make(frame, host, tpid, tci));
        assert!(findings.ids.iter().all(|finding| finding.alert.signature != TITLE));
    }
    let batch = engine.inspect(&make(4, 4, 0x8100, 0xb014));
    let finding = batch.ids.iter().find(|finding| finding.alert.signature == TITLE).unwrap();
    assert_eq!(finding.related_packets, [1, 3]);
}

#[test]
fn ntlm_fanout_rearms_after_diversity_declines_without_reusing_a_reviewed_alert() {
    let mut core = AnalysisCore::default();
    let payload = cases_3::smb2_ntlm_request(3);
    let observe = |core: &mut AnalysisCore, no, time, target, vlan| {
        let mut packet = ipv4_tcp_packet(no, no as u32 * 1024, 0x18, &payload);
        packet.bytes[26..34].copy_from_slice(&[10, 0, 0, 9, 10, 0, 2, target]);
        packet.bytes[36..38].copy_from_slice(&445_u16.to_be_bytes());
        packet.src = "10.0.0.9".into();
        packet.dst = format!("10.0.2.{target}");
        packet.dst_port = Some(445);
        packet.vlan_id = Some(vlan);
        packet.timestamp = time;
        core.analyze(&packet);
    };
    let episodes = |core: &AnalysisCore| core.alert_center.items.iter()
        .filter(|alert| alert.title == "NTLM authentication fan-out").cloned().collect::<Vec<_>>();

    for (no, time, target) in [(1, 1.0, 1), (2, 3.0, 2), (3, 4.0, 3)] {
        observe(&mut core, no, time, target, 10);
    }
    let first = episodes(&core).pop().unwrap();
    assert!(core.alert_center.set_disposition(first.id, first.capture_id.as_deref(), AlertDisposition::Benign));
    // Sustained activity dips to two active targets before another host joins.
    observe(&mut core, 4, 302.0, 4, 10);
    assert_eq!(episodes(&core).len(), 1);
    observe(&mut core, 5, 602.0, 5, 10);
    observe(&mut core, 6, 603.0, 6, 20);
    observe(&mut core, 7, 603.0, 7, 10);
    assert_eq!(episodes(&core).len(), 1);
    observe(&mut core, 8, 604.0, 8, 10);
    let alerts = episodes(&core);
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0].disposition, AlertDisposition::Benign);
    assert_eq!(alerts[0].packet_refs, [1, 2, 3]);
    assert_ne!(alerts[0].id, alerts[1].id);
    assert_eq!(alerts[1].disposition, AlertDisposition::New);
    assert_eq!(alerts[1].packet_refs, [5, 7, 8]);
    assert_eq!(alerts[1].provenance.as_ref().unwrap().revision, 5);
    assert!(alerts[1].detail.contains("outcomes unverified"));
}

#[cfg(feature = "terminal-ui")]
#[test]
fn opted_in_ntlm_fanout_archives_only_cited_requests_after_history_rollover() {
    use super::archive_fixture::{finish, roll_history, start};
    use packrat_tui::net::parser::parse_ethernet;
    use packrat_tui::storage::packet_archive::PacketArchive;

    let rule = "smb2.ntlm_authentication_fanout";
    let payload = cases_3::smb2_ntlm_request(3);
    let request = |no, timestamp, target, vlan| {
        let mut bytes = ipv4_tcp_packet(no, no as u32 * 1024, 0x18, &payload).bytes;
        bytes[26..34].copy_from_slice(&[10, 0, 0, 9, 10, 0, 2, target]);
        bytes[36..38].copy_from_slice(&445_u16.to_be_bytes());
        bytes.splice(12..12, [0x81, 0, 0, vlan]);
        parse_ethernet(&bytes, no, timestamp)
    };
    for selected in [false, true] {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("archive");
        let rules = vec![if selected { rule } else { "smb2.logon_failure_burst" }.into()];
        let mut app = start(&path, rules);
        let first = request(2, 2.0, 1, 10);
        let second = request(4, 5.0, 2, 10);
        for packet in [request(1, 1.0, 1, 10), first.clone(), request(3, 4.0, 3, 20), second.clone()] {
            app.inject_packet(packet);
        }
        let trigger = roll_history(&mut app, 5);
        let last = request(trigger, 4.5, 3, 10);
        app.inject_packet(last.clone());
        finish(&mut app);
        let alert = app.query_core(|core| core.alert_center.items.iter()
            .find(|item| item.provenance.as_ref().is_some_and(|p| p.rule_id == rule)).cloned())
            .unwrap().unwrap();
        assert_eq!(alert.packet_refs, [2, 4, trigger]);
        let scope = alert.capture_id.unwrap();
        let mut archive = PacketArchive::open_readonly(&path).unwrap();
        assert_eq!(archive.count().unwrap(), if selected { 3 } else { 0 });
        for packet in [first, second, last] {
            let recovered = archive.packet_for_capture(&scope, packet.no).unwrap();
            assert_eq!(recovered.map(|frame| frame.bytes), selected.then_some(packet.bytes));
        }
    }
}
