use super::*;
use packrat_tui::engine::AnalysisCore;
use packrat_tui::net::parser::parse_ethernet;

#[test]
fn lldp_chassis_changes_compare_only_claims_on_the_same_tag_path() {
    const TITLE: &str = "LLDP chassis identity changed";
    let make = |no, tpid: u16, tci: u16, chassis| {
        let mut raw = lldp_packet(no, [2, 1, 2, 3, 4, 5], chassis).bytes;
        raw.splice(12..12, [tpid, tci].into_iter().flat_map(u16::to_be_bytes));
        parse_ethernet(&raw, no, no as f64)
    };
    let mut core = AnalysisCore::default();
    core.analyze(&make(1, 0x8100, 20, b"a"));
    core.analyze(&make(2, 0x88a8, 20, b"b"));
    assert!(core.alert_center.items.iter().all(|alert| alert.title != TITLE));
    core.analyze(&make(3, 0x8100, 0xb014, b"c"));
    core.analyze(&make(4, 0x88a8, 0xb014, b"d"));
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == TITLE).collect();
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0].packet_refs, [1, 3]);
    assert_eq!(alerts[1].packet_refs, [2, 4]);
}

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

#[rstest::rstest]
#[case(2.0)]
#[case(3.0)]
fn withdrawn_lldp_identity_ignores_reordered_claims(#[case] delayed_time: f64) {
    const TITLE: &str = "LLDP chassis identity changed";
    let mac = [2, 1, 2, 3, 4, 5];
    let mut core = AnalysisCore::default();
    let mut shutdown = lldp_packet(3, mac, b"a");
    shutdown.bytes[24..26].fill(0);
    let mut delayed = lldp_packet(2, mac, b"a");
    delayed.timestamp = delayed_time;
    for packet in [lldp_packet(1, mac, b"a"), shutdown, delayed, lldp_packet(4, mac, b"b")] {
        core.analyze(&packet);
    }
    assert!(core.alert_center.items.iter().all(|alert| alert.title != TITLE));

    core.analyze(&lldp_packet(5, mac, b"c"));
    let alert = core.alert_center.items.iter().find(|alert| alert.title == TITLE).unwrap();
    assert_eq!(alert.packet_refs, [4, 5]);
}

#[test]
fn withdrawn_lldp_identity_yields_capacity_to_a_new_neighbor() {
    let make = |no, host: u16, chassis: &[u8]| {
        let [high, low] = host.to_be_bytes();
        let mut packet = lldp_packet(no, [2, 1, 2, 3, high, low], chassis);
        packet.timestamp = 1.0;
        packet
    };
    let mut core = AnalysisCore::default();
    for host in 1..=1024 {
        core.analyze(&make(u64::from(host), host, b"a"));
    }
    let mut shutdown = make(1025, 1, b"a");
    shutdown.bytes[24..26].fill(0);
    core.analyze(&shutdown);
    core.analyze(&make(1026, 1025, b"a"));
    core.analyze(&make(1027, 1025, b"b"));
    let alert = core.alert_center.items.iter()
        .find(|alert| alert.title == "LLDP chassis identity changed").unwrap();
    assert_eq!(alert.packet_refs, [1026, 1027]);
}

#[cfg(feature = "terminal-ui")]
#[rstest::rstest]
#[case(false)]
#[case(true)]
fn lldp_archive_preserves_only_the_live_same_scope_comparison(#[case] selected: bool) {
    use super::archive_fixture::{finish, roll_history, start};
    use packrat_tui::storage::packet_archive::PacketArchive;

    const RULE: &str = "lldp.chassis_identity_change";
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("archive");
    let mut app = start(&path, selected.then(|| RULE.to_owned()).into_iter().collect());
    let make = |no, time, vlan: u16, chassis: &[u8], withdraw| {
        let mut wire = lldp_packet(no, [2, 1, 2, 3, 4, 5], chassis).bytes;
        if withdraw {
            let ttl = wire.len() - 4;
            wire[ttl..ttl + 2].fill(0);
        }
        let [high, low] = vlan.to_be_bytes();
        wire.splice(12..12, [0x81, 0, high, low]);
        parse_ethernet(&wire, no, time)
    };
    app.inject_packet(make(1, 1.0, 10, b"a", false));
    app.inject_packet(make(2, 2.0, 20, b"b", false));
    let prior = make(3, 3.0, 10, b"a", false);
    app.inject_packet(prior.clone());
    app.inject_packet(make(4, 4.0, 20, b"b", true));
    let frame = roll_history(&mut app, 5);
    app.inject_packet(make(frame, 7.0, 20, b"c", false));
    let trigger = make(frame + 1, 8.0, 10, b"d", false);
    app.inject_packet(trigger.clone());
    app.inject_packet(make(frame + 2, 45.0, 10, b"e", false));
    finish(&mut app);

    let alert = app.query_core(|core| {
        let mut alerts = core.alert_center.items.iter()
            .filter(|item| item.provenance.as_ref().is_some_and(|rule| rule.rule_id == RULE));
        let alert = alerts.next().unwrap().clone();
        assert!(alerts.next().is_none());
        alert
    }).unwrap();
    assert_eq!(alert.packet_refs, [prior.no, trigger.no]);
    let scope = alert.capture_id.unwrap();
    let mut archive = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(archive.count().unwrap(), if selected { 2 } else { 0 });
    for packet in [prior, trigger] {
        let retained = archive.packet_for_capture(&scope, packet.no).unwrap();
        assert_eq!(retained.map(|packet| packet.bytes), selected.then_some(packet.bytes));
    }
}
