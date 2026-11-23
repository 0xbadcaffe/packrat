use super::*;
use packrat_tui::engine::AnalysisCore;
use std::net::Ipv6Addr;

const ROUTER_LINK_TITLE: &str = "IPv6 default router Ethernet source changed";

fn router_link_packet(no: u64, time: f64, vlan: u16, host: u8, lifetime: u16) -> Packet {
    let mut data = [0_u8; 16];
    data[0] = 134;
    data[6..8].copy_from_slice(&lifetime.to_be_bytes());
    let source = "fe80::1".parse::<Ipv6Addr>().unwrap().octets();
    let mut packet = ipv6_control_packet(no, [2, 1, 2, 3, 4, host], source, 255, &data);
    let sum = packet.bytes[22..54].chunks_exact(2).chain(data.chunks_exact(2))
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum::<u32>() + data.len() as u32 + 58;
    let folded = (sum >> 16) + (sum & 0xffff);
    let checksum = !(((folded >> 16) + (folded & 0xffff)) as u16);
    packet.bytes[56..58].copy_from_slice(&checksum.to_be_bytes());
    packet.timestamp = time;
    packet.vlan_id = Some(vlan);
    packet
}

#[test]
fn default_router_link_change_requires_scoped_active_advertisements() {
    let mut core = AnalysisCore::default();
    core.analyze(&router_link_packet(1, 1.0, 10, 1, 90));
    core.analyze(&router_link_packet(2, 2.0, 20, 2, 90));
    let mut invalid_checksum = router_link_packet(3, 3.0, 10, 3, 90);
    invalid_checksum.bytes[56] ^= 1;
    core.analyze(&invalid_checksum);
    let mut wrong_hop_limit = router_link_packet(4, 4.0, 10, 4, 90);
    wrong_hop_limit.bytes[21] = 64;
    core.analyze(&wrong_hop_limit);
    core.analyze(&router_link_packet(5, 5.0, 10, 5, 0));
    assert!(!core.alert_center.items.iter().any(|alert| alert.title == ROUTER_LINK_TITLE));

    core.analyze(&router_link_packet(6, 6.0, 10, 6, 90));
    core.analyze(&router_link_packet(7, 0.5, 10, 7, 90));
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == ROUTER_LINK_TITLE).collect();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].packet_refs, [1, 6]);
    assert_eq!(alerts[0].severity, "MEDIUM");
    assert_eq!(alerts[0].provenance.as_ref().unwrap().rule_id, "ipv6.ra_router_link_change");
    assert!(alerts[0].detail.contains("endpoint route changes were not verified"));
}

#[rstest]
#[case(false)]
#[case(true)]
fn default_router_link_change_does_not_flag_expired_or_withdrawn_claims(#[case] withdrawn: bool) {
    let mut core = AnalysisCore::default();
    core.analyze(&router_link_packet(1, 1.0, 10, 1, 30));
    if withdrawn {
        core.analyze(&router_link_packet(2, 5.0, 10, 1, 0));
        core.analyze(&router_link_packet(3, 6.0, 10, 2, 30));
    } else {
        core.analyze(&router_link_packet(2, 31.0, 10, 2, 30));
    }
    assert!(!core.alert_center.items.iter().any(|alert| alert.title == ROUTER_LINK_TITLE));
}

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
    core.analyze(&make(6, 8.0, 10, 6, 255, |_| {}));
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

#[test]
fn ndp_binding_changes_accept_later_frames_at_the_same_time() {
    let target = "2001:db8::5".parse::<Ipv6Addr>().unwrap().octets();
    let mut core = AnalysisCore::default();
    for (no, host) in [(1, 1), (2, 2), (1, 3), (3, 4)] {
        let mac = [2, 1, 2, 3, 4, host];
        let mut packet = ipv6_control_packet(no, mac, target, 255, &neighbor_advertisement(target, mac));
        packet.timestamp = 1.0;
        core.analyze(&packet);
    }
    let alert = core.alert_center.items.iter()
        .find(|alert| alert.title == "IPv6 neighbor binding changed").unwrap();
    assert_eq!(alert.hit_count, 2);
    assert_eq!(alert.packet_refs, [1, 2, 3]);
}
