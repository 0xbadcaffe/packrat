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

#[test]
fn ntlm_fanout_uses_only_tcp_data_with_ack_and_matching_ports() {
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
    assert!(engine.ids_alerts.iter().all(|alert| alert.signature != TITLE));
    engine.update(&make(6, 6, 0x18, 445));
    engine.update(&make(7, 7, 0x18, 445));
    assert!(engine.ids_alerts.iter().all(|alert| alert.signature != TITLE));
    let batch = engine.inspect(&make(8, 8, 0x19, 445));
    let finding = batch.ids.iter().find(|finding| finding.alert.signature == TITLE).unwrap();
    assert_eq!(finding.related_packets, [6, 7]);
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
    assert_eq!(alerts[1].provenance.as_ref().unwrap().revision, 3);
    assert!(alerts[1].detail.contains("outcomes unverified"));
}
