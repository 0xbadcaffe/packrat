use super::*;
use packrat_tui::engine::AnalysisCore;
use std::net::Ipv6Addr;

#[test]
fn router_advertisement_rate_keeps_only_scoped_valid_samples() {
    const TITLE: &str = "IPv6 router advertisement flood";
    let source = "fe80::1".parse::<Ipv6Addr>().unwrap().octets();
    let make = |no, vlan, hop, options: &[u8]| {
        let mut data = vec![0; 16];
        data[0] = 134;
        data.extend(options);
        let mut packet = ipv6_control_packet(no, [2, 1, 2, 3, 4, 5], source, hop, &data);
        packet.vlan_id = Some(vlan);
        packet.timestamp = no as f64 / 1000.0;
        packet
    };
    let mut core = AnalysisCore::default();
    for no in 1..=38_u64 {
        let vlan = if no % 2 == 0 { 20 } else { 10 };
        core.analyze(&make(no, vlan, 255, &[]));
    }
    core.analyze(&make(39, 10, 64, &[]));
    core.analyze(&make(40, 10, 255, &[1, 0]));
    let mut duplicate = make(37, 10, 255, &[]);
    duplicate.timestamp = 0.041;
    core.analyze(&duplicate);
    assert!(core.alert_center.items.iter().all(|alert| alert.title != TITLE));

    core.analyze(&make(42, 10, 255, &[]));
    let alert = core.alert_center.items.iter().find(|alert| alert.title == TITLE).unwrap();
    assert_eq!(alert.packet_refs, (1..=37).step_by(2).chain([42]).collect::<Vec<_>>());
    assert_eq!(alert.severity, "MEDIUM");
    assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "ipv6.ra_rate_burst");
    assert!(alert.detail.contains("routing impact unverified"));
}

#[test]
fn ndp_binding_changes_keep_scoped_recent_valid_claims_and_both_frames() {
    const TITLE: &str = "IPv6 neighbor binding changed";
    let target = "2001:db8::5".parse::<Ipv6Addr>().unwrap().octets();
    let mut core = AnalysisCore::default();
    let make = |no, time, vlan, host, hop_limit, mutate: fn(&mut Vec<u8>)| {
        let mac = [2, 1, 2, 3, 4, host];
        let mut data = neighbor_advertisement(target, mac);
        mutate(&mut data);
        let mut packet = ipv6_control_packet(no, mac, target, hop_limit, &data);
        packet.vlan_id = Some(vlan);
        packet.timestamp = time;
        packet
    };
    for pkt in [
        make(1, 1.0, 10, 1, 255, |_| {}),
        make(2, 2.0, 20, 2, 255, |_| {}),
        make(3, 3.0, 10, 3, 64, |_| {}),
        make(4, 4.0, 10, 4, 255, |data| data.push(0)),
        make(5, 5.0, 10, 5, 255, |data| data[1] = 1),
        make(6, 6.0, 10, 6, 255, |data| data[4] = 0x40),
        make(7, 7.0, 10, 7, 255, |data| data.extend_from_within(24..32)),
    ] {
        core.analyze(&pkt);
    }
    assert!(core.alert_center.items.iter().all(|alert| alert.title != TITLE));

    core.analyze(&make(8, 8.0, 10, 8, 255, |_| {}));
    core.analyze(&make(9, 0.5, 10, 9, 255, |_| {}));
    core.analyze(&make(10, 309.0, 10, 10, 255, |_| {}));
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == TITLE).collect();
    assert_eq!(alerts.len(), 1);
    let alert = alerts[0];
    assert_eq!(alert.packet_refs, [1, 8]);
    assert_eq!(alert.hit_count, 1);
    assert_eq!(alert.severity, "MEDIUM");
    assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "ipv6.ndp_binding_change");
    assert!(alert.detail.contains("2001:db8::5"));
    assert!(alert.detail.contains("endpoint cache change was not verified"));
}
