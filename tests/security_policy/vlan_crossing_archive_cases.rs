use super::archive_fixture::{finish, roll_history, start};
use packrat_tui::net::parser::parse_ethernet;
use packrat_tui::storage::packet_archive::PacketArchive;

#[rstest::rstest]
#[case(false, false, 0)]
#[case(true, false, 2)]
#[case(true, true, 1)]
fn selective_archive_recovers_the_cited_vlan_crossing_pair(
    #[case] selected: bool,
    #[case] oversized: bool,
    #[case] saved: u64,
) {
    const RULE: &str = "vlan.mac_crossing";
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("archive");
    let mut app = start(&path, selected.then(|| RULE.to_owned()).into_iter().collect());
    let make = |no, time, outer, inner, large| {
        let mut frame = vec![0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 7,
            0x88, 0xa8, 0, outer, 0x81, 0, 0, inner, 0x88, 0xb5];
        if large { frame.resize(2049, 0); }
        parse_ethernet(&frame, no, time)
    };
    app.inject_packet(make(1, 1.0, 100, 10, false));
    app.inject_packet(make(2, 2.0, 101, 20, false));
    let previous = make(3, 3.0, 100, 10, oversized);
    app.inject_packet(previous.clone());
    let trigger = make(roll_history(&mut app, 4), 7.0, 100, 20, false);
    app.inject_packet(trigger.clone());
    finish(&mut app);

    let alert = app.query_core(|core| {
        let mut alerts = core.alert_center.items.iter()
            .filter(|item| item.provenance.as_ref().is_some_and(|rule| rule.rule_id == RULE));
        let alert = alerts.next().unwrap().clone();
        assert!(alerts.next().is_none());
        alert
    }).unwrap();
    assert_eq!(alert.packet_refs, [previous.no, trigger.no]);
    let scope = alert.capture_id.unwrap();
    let mut archive = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(archive.count().unwrap(), saved);
    for (packet, included) in [(previous, selected && !oversized), (trigger, selected)] {
        let persisted = archive.packet_for_capture(&scope, packet.no).unwrap();
        assert_eq!(persisted.map(|packet| packet.bytes), included.then_some(packet.bytes));
    }
}
