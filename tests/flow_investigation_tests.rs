#![cfg(feature = "terminal-ui")]

#[path = "support/packets.rs"]
mod packets;

use packrat_tui::analysis::stream::StreamKey;
use packrat_tui::app::{App, InvestigationItem};
use packrat_tui::net::flow::FlowKey;
use packrat_tui::tabs::Tab;

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
    assert_eq!(app.core.read().unwrap().flow_tracker.len(), 2);
    assert!(
        app.core.read().unwrap().flow_tracker
            .iter()
            .all(|flow| flow.packets == 1)
    );
}

#[test]
fn pinned_flow_resolves_the_scoped_stream_in_investigation() {
    let mut app = App::new_for_test();
    let mut packet = packets::tcp(1, 101, 0x18, b"pinned stream bytes");
    packet.vlan_id = Some(20);
    packet.outer_vlan_id = Some(10);
    let id = StreamKey::from_packet(&packet).unwrap().id();
    app.inject_packet(packet);
    app.active_tab = Tab::Flows;
    app.flows_selected = Some(0);
    assert!(app.pin_current_context());
    assert_eq!(app.active_investigation_item(), Some(&InvestigationItem::Stream(id.clone())));
    assert_eq!(app.active_investigation_stream().unwrap().key.id(), id);
    assert!(app.active_investigation_context().unwrap().available);
}

#[test]
fn pinning_udp_flow_keeps_a_packet_instead_of_inventing_a_stream() {
    let mut app = App::new_for_test();
    let mut raw = packets::tcp(1, 101, 0x18, b"").bytes;
    raw.truncate(42);
    raw[16..18].copy_from_slice(&28_u16.to_be_bytes());
    raw[23] = 17;
    raw[38..40].copy_from_slice(&8_u16.to_be_bytes());
    app.inject_packet(packrat_tui::net::parser::parse_ethernet(&raw, 1, 1.0));
    app.active_tab = Tab::Flows;
    app.flows_selected = Some(0);
    assert!(app.pin_current_context());
    assert_eq!(app.active_investigation_item(), Some(&InvestigationItem::Packet(1)));
    assert_eq!(app.active_investigation_packet().unwrap().no, 1);
}
