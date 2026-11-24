#![cfg(feature = "terminal-ui")]

#[path = "support/packets.rs"]
mod packets;

use packrat_tui::analysis::stream::StreamKey;
use packrat_tui::app::{App, InvestigationItem};
use packrat_tui::net::{flow::FlowKey, packet::Packet, parser::parse_ethernet};
use packrat_tui::tabs::Tab;

fn tagged_tcp(no: u64, sequence: u32, tpid: u16, tci: u16, payload: &[u8]) -> Packet {
    let ethernet = packets::tcp(no, sequence, 0x18, payload).bytes;
    let mut raw = ethernet[..12].to_vec();
    raw.extend(tpid.to_be_bytes());
    raw.extend(tci.to_be_bytes());
    raw.extend(&ethernet[12..]);
    parse_ethernet(&raw, no, no as f64)
}

#[test]
fn flow_review_keeps_wire_tag_paths_separate_without_splitting_priority_changes() {
    let mut app = App::new_for_test();
    let customer = tagged_tcp(1, 100, 0x8100, 20, b"customer");
    let provider = tagged_tcp(2, 100, 0x88a8, 20, b"other");
    let priority_change = tagged_tcp(3, 108, 0x8100, 0xb014, b" data");
    assert_eq!(customer.vlan_id, Some(20));
    assert_eq!(provider.vlan_id, customer.vlan_id);
    assert_ne!(FlowKey::from_packet(&customer), FlowKey::from_packet(&provider));
    assert_eq!(FlowKey::from_packet(&customer), FlowKey::from_packet(&priority_change));
    let stream_id = StreamKey::from_packet(&customer).unwrap().id();
    for packet in [customer, provider, priority_change] {
        app.inject_packet(packet);
    }
    assert_eq!(app.core.read().unwrap().flow_tracker.len(), 2);
    app.active_tab = Tab::Flows;
    app.flows_selected = Some(0);
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 24)).unwrap();
    for (index, expected) in ["VLAN 8100:20", "VLAN 88a8:20"].into_iter().enumerate() {
        app.flows_selected = Some(index);
        terminal.draw(|frame| packrat_tui::ui::draw(frame, &app)).unwrap();
        let buffer = terminal.backend().buffer();
        assert!((0..24).map(|y| (0..100).map(|x| buffer[(x, y)].symbol()).collect::<String>())
            .any(|line| line.contains(expected)), "missing {expected}");
    }
    app.flows_selected = Some(0);
    assert!(app.pin_current_context());
    let stream = app.active_investigation_stream().unwrap();
    assert_eq!(stream.key.id(), stream_id);
    assert_eq!(stream.client_data, b"customer data");
}

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
