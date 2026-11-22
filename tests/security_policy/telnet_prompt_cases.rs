use super::*;
use packrat_tui::{engine::AnalysisCore, net::parser::parse_ethernet};

#[test]
fn telnet_prompt_is_directional_and_does_not_imply_credentials() {
    const TITLE: &str = "Telnet authentication prompt";
    let make = |no, server, payload: &[u8]| {
        let mut frame = ipv4_tcp_packet(no, no as u32 * 1000, 0x18, payload).bytes;
        let (src, dst) = if server { (23_u16, 50000_u16) } else { (50000, 23) };
        frame[34..36].copy_from_slice(&src.to_be_bytes());
        frame[36..38].copy_from_slice(&dst.to_be_bytes());
        parse_ethernet(&frame, no, no as f64)
    };
    let mut core = AnalysisCore::default();
    let mut truncated = make(6, true, b"Password: not a prompt");
    truncated.bytes.truncate(54 + b"Password:".len());
    for pkt in [
        make(1, false, b"Password: "),
        make(2, true, b"Last login: "),
        make(3, true, b"Example password: shown in the handbook\r\n"),
        make(4, true, b"\xff\xfa\x18Password: hidden subnegotiation"),
        make(5, true, b"\x01Password: "),
        truncated,
    ] {
        core.analyze(&pkt);
    }
    assert!(core.alert_center.items.iter().all(|alert| {
        alert.title != TITLE && alert.title != "Cleartext Telnet Credential"
    }));

    core.analyze(&make(7, true, b"\xff\xfb\x01\xff\xfa\x18\x01\xff\xf0Welcome\r\nrouter-1 login: "));
    let mut other_vlan = make(8, true, b"Password: ");
    other_vlan.vlan_id = Some(20);
    core.analyze(&other_vlan);
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == TITLE).collect();
    assert_eq!(alerts.len(), 2);
    for (alert, frame) in [(alerts[0], 7), (alerts[1], 8)] {
        assert_eq!(alert.packet_refs, [frame]);
        assert_eq!(alert.severity, "MEDIUM");
        assert_eq!(alert.flow.unwrap().source.port(), 23);
        assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "telnet.authentication_prompt");
        assert!(alert.detail.contains("client credentials were not observed"));
    }
}
