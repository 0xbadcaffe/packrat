use super::*;
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
}
