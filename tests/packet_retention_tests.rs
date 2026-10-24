#![cfg(feature = "terminal-ui")]

use packrat_tui::app::App;
use packrat_tui::net::parser::parse_ethernet;

#[test]
fn rotating_filtered_index_keeps_packet_identity_and_rebuild_order() {
    let mut app = App::new_for_test();
    app.filter.input = "ip.src == 192.0.2.2".into();
    app.rebuild_filtered();
    for no in 1..=15_000 {
        let mut packet = parse_ethernet(&[], no, no as f64);
        packet.src = format!("192.0.2.{}", if no % 2 == 0 { 2 } else { 1 });
        app.inject_packet(packet);
    }
    assert_eq!(app.packets.len(), 10_000);
    assert_eq!(app.filtered.len(), 5_000);
    assert_eq!(app.selected_packet().unwrap().no, 5_002);
    let before = app.filtered.clone();
    app.rebuild_filtered();
    assert_eq!(app.filtered, before);
    for index in &app.filtered {
        let packet = app.retained_packet_at(*index).unwrap();
        assert_eq!(packet.no % 2, 0);
    }
}

#[test]
fn live_index_remains_ordered_after_multiple_buffer_rotations() {
    let mut app = App::new_for_test();
    app.auto_scroll = true;
    for no in 1..=30_000 {
        app.inject_packet(parse_ethernet(&[], no, no as f64));
    }
    assert_eq!(app.selected_packet().unwrap().no, 30_000);
    assert_eq!(app.filtered.len(), 10_000);
    let numbers: Vec<_> = app
        .filtered
        .iter()
        .map(|index| app.retained_packet_at(*index).unwrap().no)
        .collect();
    assert_eq!(numbers, (20_001..=30_000).collect::<Vec<_>>());
}
