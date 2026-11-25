use super::{checksummed_ipv6_control_packet, ipv6_control_packet};
use packrat_tui::engine::AnalysisCore;

#[test]
fn invalid_ndp_hop_limit_requires_a_complete_message_and_remains_scoped() {
    const TITLE: &str = "Invalid IPv6 neighbor discovery hop limit";
    let mac = [2, 0, 0, 0, 0, 1];
    let source = "fe80::1".parse::<std::net::Ipv6Addr>().unwrap().octets();
    let wire = |no, hop, payload: &[u8]| checksummed_ipv6_control_packet(no, mac, source, hop, payload);
    let solicitation = [133, 0, 0, 0, 0, 0, 0, 0];
    let mut core = AnalysisCore::default();
    core.analyze(&ipv6_control_packet(1, mac, source, 64, &[133]));
    core.analyze(&wire(2, 255, &solicitation));
    let mut truncated = wire(3, 64, &solicitation);
    truncated.bytes[19] += 8;
    core.analyze(&truncated);
    let mut wrong_code = solicitation;
    wrong_code[1] = 1;
    core.analyze(&wire(4, 64, &wrong_code));
    let mut malformed_option = solicitation.to_vec();
    malformed_option.extend([1, 0, 2, 0, 0, 0, 0, 1]);
    core.analyze(&wire(5, 64, &malformed_option));
    let mut fragment = vec![58, 0, 0, 8, 0, 0, 0, 1];
    fragment.extend(solicitation);
    let mut fragment = ipv6_control_packet(6, mac, source, 64, &fragment);
    fragment.bytes[20] = 44;
    core.analyze(&fragment);
    let mut corrupt = wire(7, 64, &solicitation);
    corrupt.bytes[56] ^= 1;
    core.analyze(&corrupt);
    assert!(core.alert_center.items.iter().all(|alert| alert.title != TITLE));

    for (no, vlan) in [(8, 10_u16), (9, 20), (10, 10)] {
        let mut packet = wire(no, 64, &solicitation);
        packet.bytes.splice(12..12, [0x81, 0, 0, vlan as u8]);
        let packet = packrat_tui::net::parser::parse_ethernet(&packet.bytes, no, no as f64);
        assert_eq!(packet.vlan_id, Some(vlan));
        core.analyze(&packet);
    }
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == TITLE).collect();
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0].hit_count, 2);
    assert_eq!(alerts[0].packet_refs, [8, 10]);
    assert_eq!(alerts[1].packet_refs, [9]);
    for alert in alerts {
        assert_eq!(alert.severity, "MEDIUM");
        assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "ipv6.ndp_invalid_hop_limit");
        assert_eq!(alert.provenance.as_ref().unwrap().revision, 3);
        assert!(alert.detail.contains("Router Solicitation from fe80::1 to ff02::1"));
    }
    assert!(core.incidents.incidents.is_empty());
}
