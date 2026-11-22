use super::*;
use packrat_tui::engine::AnalysisCore;
use std::net::Ipv6Addr;

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
