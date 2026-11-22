use super::*;
use packrat_tui::engine::AnalysisCore;
use packrat_tui::net::parser::parse_ethernet;

#[test]
fn lldp_identity_changes_require_active_matching_port_and_scope() {
    const TITLE: &str = "LLDP chassis identity changed";
    let make = |no, vlan: u16, chassis: &[u8]| {
        let mut wire = lldp_packet(no, [2, 1, 2, 3, 4, 5], chassis).bytes;
        let [high, low] = vlan.to_be_bytes();
        wire.splice(12..12, [0x81, 0, high, low]);
        let packet = parse_ethernet(&wire, no, no as f64);
        assert_eq!(packet.vlan_id, Some(vlan));
        packet
    };
    let mut core = AnalysisCore::default();
    core.analyze(&make(1, 10, b"a"));
    core.analyze(&make(2, 20, b"b"));
    let mut other_port = make(3, 10, b"b");
    other_port.bytes[25] = 2;
    core.analyze(&other_port);
    let mut other_agent = make(4, 10, b"b");
    other_agent.bytes[5] = 3;
    core.analyze(&other_agent);
    let mut incomplete = make(5, 10, b"b");
    incomplete.bytes.pop();
    core.analyze(&incomplete);
    assert!(core.alert_center.items.iter().all(|alert| alert.title != TITLE));

    core.analyze(&make(6, 10, b"b"));
    let mut shutdown = make(7, 10, b"b");
    shutdown.bytes[28..30].fill(0);
    core.analyze(&shutdown);
    core.analyze(&make(8, 10, b"c"));
    let mut expired = make(9, 10, b"d");
    expired.timestamp = 39.0;
    core.analyze(&expired);

    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == TITLE).collect();
    assert_eq!(alerts.len(), 1);
    let alert = alerts[0];
    assert_eq!(alert.packet_refs, [1, 6]);
    assert_eq!(alert.severity, "MEDIUM");
    assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "lldp.chassis_identity_change");
    assert!(alert.detail.contains("physical identity unverified"));
}

#[test]
fn stale_lldp_shutdown_cannot_remove_a_newer_same_time_identity() {
    let mac = [2, 1, 2, 3, 4, 5];
    let mut core = AnalysisCore::default();
    let mut shutdown = lldp_packet(1, mac, b"a");
    shutdown.bytes[24..26].fill(0);
    let mut first = lldp_packet(2, mac, b"a");
    let mut replacement = lldp_packet(3, mac, b"b");
    first.timestamp = 1.0;
    shutdown.timestamp = 1.0;
    replacement.timestamp = 1.0;
    core.analyze(&first);
    core.analyze(&shutdown);
    assert!(core.alert_center.items.is_empty());
    core.analyze(&replacement);
    let alert = core.alert_center.items.iter()
        .find(|alert| alert.title == "LLDP chassis identity changed").unwrap();
    assert_eq!(alert.packet_refs, [2, 3]);
}
