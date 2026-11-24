use super::*;
use packrat_tui::{engine::AnalysisCore, net::parser::parse_ethernet};

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn ftp_anonymous_login_requires_scoped_success(#[case] distinguish_by_tpid: bool) {
    const TITLE: &str = "Anonymous FTP login accepted";
    let user = b"UsEr anonymous\r\n";
    let pass = b"PASS fixture-only\r\n";
    let first_sequence = u32::MAX - 3;
    let after_user = first_sequence.wrapping_add(user.len() as u32);
    let after_pass = after_user.wrapping_add(pass.len() as u32);
    let make = |no: u64, response: bool, sequence: u32, ack: u32, vlan, flags, payload: &[u8]| {
        let mut raw = ipv4_tcp_packet(no, sequence, flags, payload).bytes;
        let client = [192, 0, 2, 2];
        let server = [192, 0, 2, 1];
        let (src, dst, sport, dport) = if response {
            (server, client, 21_u16, 50000_u16)
        } else {
            (client, server, 50000_u16, 21_u16)
        };
        raw[26..30].copy_from_slice(&src);
        raw[30..34].copy_from_slice(&dst);
        raw[34..36].copy_from_slice(&sport.to_be_bytes());
        raw[36..38].copy_from_slice(&dport.to_be_bytes());
        raw[42..46].copy_from_slice(&ack.to_be_bytes());
        if distinguish_by_tpid {
            let tpid = if vlan == 20 { 0x88a8_u16 } else { 0x8100_u16 };
            let tci = if no % 2 == 0 { 0xb00a_u16 } else { 10_u16 };
            raw.splice(12..12, [tpid, tci].into_iter().flat_map(u16::to_be_bytes));
            return parse_ethernet(&raw, no, no as f64);
        }
        let mut packet = parse_ethernet(&raw, no, no as f64);
        packet.vlan_id = Some(vlan);
        packet
    };
    let mut core = AnalysisCore::default();
    let reply = b"230 Logged in\r\n";
    let challenge = b"331 Need password\r\n";
    for pkt in [
        make(1, true, 100, after_user, 10, 0x18, reply),
        make(2, false, first_sequence, 100, 10, 0x18, user),
        make(3, true, 200, after_user, 20, 0x18, reply),
        make(4, true, 300, after_user + 1, 10, 0x18, reply),
        make(5, true, 400, after_user, 10, 0x18, b"530 Not logged in\r\n"),
        make(6, true, 500, after_user, 10, 0x18, reply),
        make(7, false, after_user, 600, 10, 0x18, user),
        make(8, false, 20, 0, 10, 0x02, b""),
        make(9, true, 700, after_user, 10, 0x18, reply),
    ] {
        core.analyze(&pkt);
    }
    assert!(core.alert_center.items.iter().all(|alert| {
        alert.title != TITLE && alert.title != "Anonymous FTP Login"
    }));

    for pkt in [
        make(10, false, first_sequence, 800, 10, 0x18, user),
        make(11, true, 800, after_user, 10, 0x18, challenge),
        make(12, false, first_sequence, 800, 10, 0x18, user), // Retransmission.
        make(13, false, after_user, 820, 10, 0x18, pass),
        make(14, true, 900, after_pass, 10, 0x18, reply),
        make(15, true, 900, after_pass, 10, 0x18, reply), // Cannot count twice.
        make(16, false, first_sequence, 1000, 20, 0x18, user),
        make(17, true, 1000, after_user, 20, 0x18, reply),
        make(18, false, first_sequence, 1000, 20, 0x18, user),
        make(19, true, 1000, after_user, 20, 0x18, reply),
    ] {
        core.analyze(&pkt);
    }
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == TITLE).collect();
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0].packet_refs, [10, 11, 13, 14]);
    assert_eq!(alerts[1].packet_refs, [16, 17]);
    for alert in alerts {
        assert_eq!(alert.hit_count, 1);
        assert_eq!(alert.severity, "MEDIUM");
        assert_eq!(alert.flow.unwrap().source.port(), 21);
        assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "ftp.anonymous_login_accepted");
        assert_eq!(alert.provenance.as_ref().unwrap().revision, 2);
        assert!(alert.detail.contains("file access not observed"));
        assert!(!serde_json::to_string(alert).unwrap().contains("fixture-only"));
    }
}
