use super::*;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

fn dns_frame(no: u64, resolver: [u8; 4], reply: bool) -> Packet {
    let mut raw = vec![0; 42];
    raw[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    raw[14] = 0x45;
    raw[23] = 17;
    let client = [10, 0, 0, 5];
    let (src, dst, source_port, destination_port) = if reply {
        (resolver, client, 53_u16, 50_000_u16)
    } else {
        (client, resolver, 50_000, 53)
    };
    raw[26..30].copy_from_slice(&src);
    raw[30..34].copy_from_slice(&dst);
    raw[34..36].copy_from_slice(&source_port.to_be_bytes());
    raw[36..38].copy_from_slice(&destination_port.to_be_bytes());
    raw.extend([0, 42, if reply { 0x81 } else { 0x01 }, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    raw.extend_from_slice(b"\x07example\x04test\0\0\x01\0\x01");
    let length = raw.len() as u16;
    raw[16..18].copy_from_slice(&(length - 14).to_be_bytes());
    raw[38..40].copy_from_slice(&(length - 34).to_be_bytes());
    crate::net::parser::parse_ethernet(&raw, no, no as f64)
}

fn advance(app: &mut App) {
    crate::event::handle(app, Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
}

#[test]
fn enter_in_dns_transactions_visits_repeated_queries() {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Investigate;
    app.investigation_view = InvestigationView::Transactions;
    let resolver = [10, 0, 0, 53];
    let query = dns_frame(1, resolver, false);
    let retry = dns_frame(2, resolver, false);
    let reply = dns_frame(3, resolver, true);
    for frame in [&query, &retry, &reply] {
        app.core.edit().analyze(frame);
        app.packets.push_back(frame.clone());
    }
    app.worklist.pin_packet(&query).unwrap();
    for frame in [2, 3, 1] {
        advance(&mut app);
        assert_eq!(app.worklist.active_packet_no(), Some(frame));
    }
}

#[test]
fn enter_in_dns_transactions_cycles_only_available_exchange_evidence() {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Investigate;
    app.investigation_view = InvestigationView::Transactions;
    let query = dns_frame(1, [10, 0, 0, 53], false);
    let absent = dns_frame(2, [10, 0, 0, 53], true);
    let alternate = dns_frame(3, [10, 0, 0, 54], true);
    {
        let mut core = app.core.edit();
        for packet in [&query, &absent, &alternate] {
            core.analyze(packet);
        }
    }
    app.worklist.pin_packet(&dns_frame(99, [10, 0, 0, 55], false)).unwrap();
    app.worklist.pin_packet(&query).unwrap();
    app.packets.push_back(alternate);
    advance(&mut app);
    assert_eq!(app.worklist.active_packet_no(), Some(3));
    assert!(app.status_msg.as_deref().unwrap().contains("skipped 1 unavailable"));
    advance(&mut app);
    assert_eq!(app.worklist.active_packet_no(), Some(1));
    assert_eq!(app.investigation_view, InvestigationView::Transactions);
    assert!(app.worklist.retained_packet(2).is_none());
}

#[test]
fn dns_transaction_navigation_recovers_a_frame_from_the_current_archive() {
    let directory = tempfile::tempdir().unwrap();
    let mut app = App::new_for_test();
    app.set_packet_archive(crate::storage::packet_archive::ArchiveWorker::open(&directory.path().join("archive")).unwrap()).unwrap();
    let query = dns_frame(1, [10, 0, 0, 53], false);
    let reply = dns_frame(2, [10, 0, 0, 53], true);
    app.inject_packet(query.clone());
    app.inject_packet(reply.clone());
    app.packet_archive.as_mut().unwrap().finish().unwrap();
    app.packets.clear();
    app.worklist.pin_packet(&query).unwrap();
    app.active_tab = Tab::Investigate;
    app.investigation_view = InvestigationView::Transactions;
    advance(&mut app);
    assert_eq!(app.worklist.active_packet_no(), Some(2));
    assert_eq!(app.worklist.retained_packet(2).unwrap().bytes, reply.bytes);
    assert!(app.packets.is_empty());
}

#[test]
fn dns_transaction_view_and_navigation_do_not_cross_from_saved_to_live_evidence() {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Investigate;
    app.investigation_view = InvestigationView::Transactions;
    app.restored_project_max_frame = 2;
    let query = dns_frame(1, [10, 0, 0, 53], false);
    let saved_reply = dns_frame(2, [10, 0, 0, 53], true);
    let live_reply = dns_frame(3, [10, 0, 0, 54], true);
    for packet in [&query, &saved_reply, &live_reply] {
        app.core.edit().analyze(packet);
        app.worklist.pin_packet(packet).unwrap();
    }
    app.worklist.restored_packet_scopes.insert(1, "historical-capture".into());
    app.worklist.restored_packet_scopes.insert(2, "historical-capture".into());
    let mixed = app.query_core(|core| core.security.dns_exchange_for_packet(&query))
        .unwrap().unwrap();
    assert_eq!(mixed.replies.len(), 2);
    assert!(app.scope_dns_exchange(3, mixed.clone()).is_none());
    let scoped = app.scope_dns_exchange(1, mixed.clone()).unwrap();
    assert_eq!(scoped.replies.iter().map(|reply| reply.packet).collect::<Vec<_>>(), [2]);

    advance(&mut app);
    assert_eq!(app.worklist.active_packet_no(), Some(3));
    assert!(app.status_msg.as_deref().unwrap().contains("No retained DNS exchange"));
    app.worklist.pin_packet(&query).unwrap();
    advance(&mut app);
    assert_eq!(app.worklist.active_packet_no(), Some(2));
    advance(&mut app);
    assert_eq!(app.worklist.active_packet_no(), Some(1));

    app.worklist.restored_packet_scopes.insert(2, "different-capture".into());
    assert!(app.scope_dns_exchange(1, mixed).unwrap().replies.is_empty());
}
