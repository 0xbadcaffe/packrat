#[path = "support/packets.rs"]
mod packets;

use packrat_tui::app::App;
use packrat_tui::net::flow::FlowKey;

#[test]
fn flow_follow_uses_ordered_deduplicated_stream_bytes() {
    let mut app = App::new_for_test();
    for packet in [
        packets::tcp(1, 100, 0x02, &[]),
        packets::tcp(2, 106, 0x18, b"world"),
        packets::tcp(3, 101, 0x18, b"hello"),
        packets::tcp(4, 101, 0x18, b"hello"),
    ] {
        app.inject_packet(packet);
    }
    app.flows_selected = Some(0);
    app.flows_open_stream();
    let overlay = app.stream_overlay.as_ref().unwrap();
    let bytes: Vec<_> = overlay
        .segments
        .iter()
        .flat_map(|(_, bytes)| bytes.iter().copied())
        .collect();
    assert_eq!(bytes, b"helloworld");
}

#[test]
fn qinq_flow_counters_do_not_combine_tenants_with_identical_endpoints() {
    let mut app = App::new_for_test();
    let mut first = packets::tcp(1, 100, 0x18, b"first tenant");
    first.vlan_id = Some(20);
    first.outer_vlan_id = Some(10);
    let mut second = packets::tcp(2, 100, 0x18, b"second tenant");
    second.vlan_id = Some(20);
    second.outer_vlan_id = Some(11);
    assert_ne!(FlowKey::from_packet(&first), FlowKey::from_packet(&second));
    app.inject_packet(first);
    app.inject_packet(second);
    assert_eq!(app.flow_tracker.flows.len(), 2);
    assert!(
        app.flow_tracker
            .flows
            .values()
            .all(|flow| flow.packets == 1)
    );
}
