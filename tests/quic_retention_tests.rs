#[path = "support/http3.rs"]
mod support;
use packrat_tui::analysis::quic_scope::QuicScope;

fn tagged_quic(number: u64, tpid: u16) -> packrat_tui::net::packet::Packet {
    let frame = support::quic_packet(number);
    let mut bytes = frame.bytes[..12].to_vec();
    bytes.extend(tpid.to_be_bytes());
    bytes.extend(20_u16.to_be_bytes());
    bytes.extend(&frame.bytes[12..]);
    packrat_tui::net::parser::parse_ethernet(&bytes, number, number as f64)
}

#[test]
fn same_quic_destination_id_does_not_merge_observed_tag_paths() {
    let mut scope = QuicScope::default();
    scope.ingest(&tagged_quic(1, 0x8100));
    scope.ingest(&tagged_quic(2, 0x88a8));
    assert_eq!(scope.connections.len(), 2);
    assert!(scope.all().iter().all(|connection| connection.packets == 1));
    assert!(scope.for_packet(&tagged_quic(2, 0x8100)).is_none());
    assert!(scope.for_packet(&tagged_quic(2, 0x88a8)).is_some());
}

#[test]
fn quic_packet_links_expire_and_clear_without_falling_back_to_ids() {
    let mut scope = QuicScope::default();
    for frame in 1..=130 {
        scope.ingest(&support::quic_packet(frame));
    }
    assert!(scope.for_packet(&support::quic_packet(2)).is_none());
    assert!(scope.for_packet(&support::quic_packet(3)).is_some());
    assert!(scope.for_packet(&support::quic_packet(130)).is_some());
    assert!(scope.for_packet(&support::quic_packet(131)).is_none());
    scope.clear();
    assert!(scope.for_packet(&support::quic_packet(130)).is_none());
}

#[test]
fn quic_inventory_does_not_treat_bytes_after_the_udp_datagram_as_payload() {
    let mut scope = QuicScope::default();
    let mut frame = support::quic_packet(1);
    frame.bytes[38..40].copy_from_slice(&8_u16.to_be_bytes());
    scope.ingest(&frame);
    assert!(scope.connections.is_empty());
}

#[cfg(feature = "terminal-ui")]
#[test]
fn encrypted_context_shows_only_quic_linked_to_the_selected_frame() {
    use packrat_tui::{app::{App, InvestigationView}, tabs::Tab, ui};
    use ratatui::{Terminal, backend::TestBackend};

    let mut app = App::new_for_test();
    app.inject_packet(support::quic_packet(1));
    let mut other = support::quic_packet(2);
    other.bytes[48] = 9;
    app.inject_packet(other);
    let mut unrelated = support::quic_packet(3);
    unrelated.bytes[34..38].copy_from_slice(&[0xd4, 0x31, 0, 53]);
    app.inject_packet(packrat_tui::net::parser::parse_ethernet(&unrelated.bytes, 3, 3.0));
    app.active_tab = Tab::Investigate;
    app.investigation_view = InvestigationView::Encrypted;
    let mut terminal = Terminal::new(TestBackend::new(100, 26)).unwrap();
    for (selection, linked) in [(0, true), (2, false)] {
        app.selected = Some(selection);
        terminal.draw(|frame| ui::draw(frame, &app)).unwrap();
        let buffer = terminal.backend().buffer();
        let text: String = (0..26).map(|y| (0..100).map(|x| buffer[(x, y)].symbol()).collect::<String>()).collect();
        assert!(!text.contains("ID: 09020304"), "{text}");
        assert_eq!(text.contains("ID: 01020304"), linked, "{text}");
    }
}

#[test]
fn quic_inventory_evicts_first_seen_connections_without_unbounded_growth() {
    let mut scope = QuicScope::default();
    for number in 1..=1100u32 {
        let mut packet = support::quic_packet(number as u64);
        packet.bytes[48..52].copy_from_slice(&number.to_be_bytes());
        scope.ingest(&packet);
    }
    assert_eq!(scope.connections.len(), 1024);
    assert_eq!(scope.evicted_connections, 76);
    assert!(!scope.connections.contains_key("00000001"));
    assert!(scope.connections.contains_key(&format!("{:08x}", 1100)));
    scope.clear();
    assert_eq!(scope.evicted_connections, 0);
    assert!(scope.connections.is_empty());
}

#[test]
fn address_churn_is_bounded_and_explicitly_marked() {
    let mut scope = QuicScope::default();
    for number in 1..=100 {
        let mut packet = support::quic_packet(number);
        packet.src = format!("192.0.2.{number}");
        scope.ingest(&packet);
    }
    let connection = scope.all()[0];
    assert_eq!(connection.addresses.len(), 32);
    assert!(connection.addresses_truncated);
    assert!(connection.migration_observed());
    assert_eq!(connection.packets, 100);
}
