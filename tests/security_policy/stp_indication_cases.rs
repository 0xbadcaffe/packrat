use packrat_tui::{engine::AnalysisCore, net::parser::parse_ethernet};

#[test]
fn stp_indications_keep_separate_review_state_for_different_tag_paths() {
    use packrat_tui::analysis::alert_center::AlertDisposition;

    let make = |no, tpid: u16, tci: u16| {
        let mut raw = vec![1, 0x80, 0xc2, 0, 0, 0, 2, 0, 0, 0, 0, 1];
        raw.extend([tpid, tci, 7].into_iter().flat_map(u16::to_be_bytes));
        raw.extend([0x42, 0x42, 3, 0, 0, 0, 0x80]);
        parse_ethernet(&raw, no, no as f64)
    };
    let mut core = AnalysisCore::default();
    core.analyze(&make(1, 0x8100, 20));
    let first = &core.alert_center.items[0];
    let (id, capture) = (first.id, first.capture_id.clone());
    assert!(core.alert_center.set_disposition(id, capture.as_deref(), AlertDisposition::Benign));
    core.analyze(&make(2, 0x88a8, 20));
    core.analyze(&make(3, 0x8100, 0xb014));
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == "STP topology change").collect();
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0].packet_refs, [1, 3]);
    assert_eq!(alerts[0].disposition, AlertDisposition::Benign);
    assert_eq!(alerts[1].packet_refs, [2]);
    assert_eq!(alerts[1].disposition, AlertDisposition::New);
}

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
        let pkt = parse_ethernet(&raw, no, no as f64);
        assert_eq!(pkt.vlan_id, vlan);
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
