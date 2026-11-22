use packrat_tui::{engine::AnalysisCore, net::parser::parse_ethernet};

#[test]
fn stp_indications_validate_bpdu_format_and_do_not_count_acknowledgements() {
    const TITLE: &str = "STP topology change";
    let wire = |no, vlan: Option<u16>, bpdu: &[u8]| {
        let mut raw = vec![1, 0x80, 0xc2, 0, 0, 0, 2, 0, 0, 0, 0, 1];
        if let Some(vlan) = vlan {
            raw.extend([0x81, 0]);
            raw.extend(vlan.to_be_bytes());
        }
        raw.extend(((bpdu.len() + 3) as u16).to_be_bytes());
        raw.extend([0x42, 0x42, 0x03]);
        raw.extend(bpdu);
        let mut pkt = parse_ethernet(&raw, no, no as f64);
        pkt.vlan_id = vlan;
        pkt
    };
    let mut core = AnalysisCore::default();
    let mut configuration = [0_u8; 35];
    configuration[4] = 0x80;
    core.analyze(&wire(1, None, &configuration));
    let mut rstp = [0_u8; 36];
    rstp[2..5].copy_from_slice(&[2, 2, 1]);
    core.analyze(&wire(2, None, &rstp[..35]));
    let mut mstp = [0_u8; 102];
    mstp[2..5].copy_from_slice(&[3, 2, 1]);
    mstp[37] = 63;
    core.analyze(&wire(3, None, &mstp));
    core.analyze(&wire(4, None, &[0, 0, 2, 0x80]));
    let mut truncated = wire(5, None, &rstp);
    truncated.bytes.pop();
    core.analyze(&truncated);
    assert!(core.alert_center.items.iter().all(|alert| alert.title != TITLE));

    core.analyze(&wire(6, None, &[0, 0, 0, 0x80]));
    configuration[4] = 1;
    core.analyze(&wire(7, None, &configuration));
    core.analyze(&wire(8, Some(10), &rstp));
    core.analyze(&wire(9, Some(20), &rstp));
    mstp[37] = 64;
    core.analyze(&wire(10, None, &mstp));
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == TITLE).collect();
    assert_eq!(alerts.iter().map(|alert| alert.packet_no).collect::<Vec<_>>(), [6, 7, 8, 9, 10]);
    for alert in alerts {
        assert_eq!(alert.packet_refs, [alert.packet_no]);
        assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "stp.topology_change_indication");
        assert!(alert.detail.contains("forwarding changes were not verified"));
    }
}
