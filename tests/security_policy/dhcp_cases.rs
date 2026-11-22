use super::*;
use packrat_tui::engine::AnalysisCore;
use packrat_tui::net::packet::CaptureMetadata;

const BURST: &str = "DHCP client identity burst";

fn discovery(frame: u64, identity: u8, timestamp: f64) -> Packet {
    let mac = [2, 0, 0, 0, 0, identity];
    let mut packet = dhcp_packet(frame, 1, mac, mac, None);
    packet.timestamp = timestamp;
    packet
}

#[test]
fn dhcp_identity_burst_keeps_one_frame_per_identity_and_explains_uncertainty() {
    let mut core = AnalysisCore::default();
    for frame in 1..=80 {
        core.analyze(&discovery(frame, 0, 1.0));
    }
    assert!(core.alert_center.items.iter().all(|alert| alert.title != BURST));
    for identity in 1..=63 {
        core.analyze(&discovery(80 + u64::from(identity), identity, 2.0));
    }
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == BURST).collect();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].severity, "MEDIUM");
    assert!(alerts[0].detail.contains("lease exhaustion was not observed"));
    assert_eq!(alerts[0].packet_refs, std::iter::once(1).chain(81..=143).collect::<Vec<_>>());
    let rule = alerts[0].provenance.as_ref().unwrap();
    assert_eq!(rule.rule_id, "dhcp.discover_identity_burst");
    assert_eq!(rule.revision, 2);
}

#[rstest]
#[case(true)]
#[case(false)]
fn dhcp_observations_do_not_combine_interfaces_or_outer_vlans(#[case] separate_interfaces: bool) {
    let mut engine = SecurityEngine::default();
    for identity in 0..64 {
        let mut packet = discovery(u64::from(identity) + 1, identity, 1.0);
        if separate_interfaces {
            packet.capture = Some(CaptureMetadata {
                timestamp: None, wire_length: packet.bytes.len() as u32,
                captured_length: packet.bytes.len() as u32, link_type: 1,
                section_id: 0, interface_id: u32::from(identity % 2),
                interface_name: None, comments: Vec::new(),
            });
        } else {
            packet.outer_vlan_id = Some(u16::from(identity % 2) + 100);
        }
        engine.update(&packet);
    }
    assert!(engine.ids_alerts.iter().all(|alert| alert.signature != BURST));
}

#[test]
fn dhcp_burst_uses_capture_window_and_rearms_after_distinct_clients_expire() {
    let mut engine = SecurityEngine::default();
    for identity in 0..64 {
        engine.update(&discovery(u64::from(identity) + 1, identity, 1.0));
    }
    engine.update(&discovery(65, 100, 11.1));
    for identity in 0..64 {
        engine.update(&discovery(u64::from(identity) + 66, identity, 1.0));
    }
    assert_eq!(engine.ids_alerts.iter().filter(|alert| alert.signature == BURST).count(), 1);
    for identity in 0..63 {
        let result = engine.inspect(&discovery(u64::from(identity) + 130, identity, 11.2));
        if identity == 62 {
            let finding = result.ids.iter().find(|finding| finding.alert.signature == BURST).unwrap();
            assert_eq!(finding.related_packets, std::iter::once(65).chain(130..=192).collect::<Vec<_>>());
        } else {
            assert!(result.ids.iter().all(|finding| finding.alert.signature != BURST));
        }
    }
}
