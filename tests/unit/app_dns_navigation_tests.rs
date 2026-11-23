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
    raw.extend([
        0,
        42,
        if reply { 0x81 } else { 0x01 },
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
    ]);
    raw.extend_from_slice(b"\x07example\x04test\0\0\x01\0\x01");
    let length = raw.len() as u16;
    raw[16..18].copy_from_slice(&(length - 14).to_be_bytes());
    raw[38..40].copy_from_slice(&(length - 34).to_be_bytes());
    crate::net::parser::parse_ethernet(&raw, no, no as f64)
}

fn advance(app: &mut App) {
    crate::event::handle(
        app,
        Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
    );
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
fn enter_in_dns_transactions_visits_each_timing_retry_segment_without_crossing_scopes() {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Investigate;
    app.investigation_view = InvestigationView::Transactions;
    let queries = two_dns_messages(false);
    let replies = two_dns_messages(true);
    let first_message = |data: &[u8]| 2 + u16::from_be_bytes([data[0], data[1]]) as usize;
    let query = &queries[..first_message(&queries)];
    let reply = &replies[..first_message(&replies)];
    let retry_seq = 101 + query.len() as u32;
    for (mut packet, timestamp) in [
        (tcp_frame(1, 100, 0x02, false, &[]), 1.0),
        (tcp_frame(2, 200, 0x12, true, &[]), 2.0),
        (tcp_frame(3, 101, 0x18, false, query), 3.0),
        (tcp_frame(4, retry_seq, 0x18, false, &query[..5]), 27.0),
        (tcp_frame(5, retry_seq + 5, 0x18, false, &query[5..]), 28.0),
        (tcp_frame(6, 201, 0x18, true, reply), 34.0),
    ] {
        packet.timestamp = timestamp;
        app.core.edit().analyze(&packet);
        if packet.no == 4 {
            app.worklist.pin_packet(&packet).unwrap();
        }
        app.packets.push_back(packet);
    }
    for frame in [5, 6, 3, 4] {
        advance(&mut app);
        assert_eq!(app.worklist.active_packet_no(), Some(frame));
    }
    {
        use ratatui::{Terminal, backend::TestBackend};
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
        terminal.draw(|frame| crate::ui::draw(frame, &app)).unwrap();
        let rendered = terminal.backend().buffer().content().iter()
            .map(|cell| cell.symbol()).collect::<String>();
        assert!(rendered.contains("Retry kept query eligible #5"));
        assert!(rendered.contains("Retry bytes #4"));
    }
    app.worklist.restored_packet_scopes.insert(5, "other-capture".into());
    let packet = app.active_investigation_packet().unwrap();
    assert!(app.query_core(|core| app.dns_exchanges(core, packet)).unwrap().is_empty());
    advance(&mut app);
    assert_eq!(app.worklist.active_packet_no(), Some(4));
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
    app.worklist
        .pin_packet(&dns_frame(99, [10, 0, 0, 55], false))
        .unwrap();
    app.worklist.pin_packet(&query).unwrap();
    app.packets.push_back(alternate);
    advance(&mut app);
    assert_eq!(app.worklist.active_packet_no(), Some(3));
    assert!(
        app.status_msg
            .as_deref()
            .unwrap()
            .contains("skipped 1 unavailable")
    );
    advance(&mut app);
    assert_eq!(app.worklist.active_packet_no(), Some(1));
    assert_eq!(app.investigation_view, InvestigationView::Transactions);
    assert!(app.worklist.retained_packet(2).is_none());
}

#[test]
fn dns_transaction_navigation_recovers_a_frame_from_the_current_archive() {
    let directory = tempfile::tempdir().unwrap();
    let mut app = App::new_for_test();
    app.set_packet_archive(
        crate::storage::packet_archive::ArchiveWorker::open(&directory.path().join("archive"))
            .unwrap(),
    )
    .unwrap();
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
    app.worklist
        .restored_packet_scopes
        .insert(1, "historical-capture".into());
    app.worklist
        .restored_packet_scopes
        .insert(2, "historical-capture".into());
    let mixed = app
        .query_core(|core| core.security.dns_exchange_for_packet(&query))
        .unwrap()
        .unwrap();
    assert_eq!(mixed.replies.len(), 2);
    assert!(app.scope_dns_exchange(3, mixed.clone()).is_none());
    let scoped = app.scope_dns_exchange(1, mixed.clone()).unwrap();
    assert_eq!(
        scoped
            .replies
            .iter()
            .map(|reply| reply.packet)
            .collect::<Vec<_>>(),
        [2]
    );

    advance(&mut app);
    assert_eq!(app.worklist.active_packet_no(), Some(3));
    assert!(
        app.status_msg
            .as_deref()
            .unwrap()
            .contains("No retained DNS exchange")
    );
    app.worklist.pin_packet(&query).unwrap();
    advance(&mut app);
    assert_eq!(app.worklist.active_packet_no(), Some(2));
    advance(&mut app);
    assert_eq!(app.worklist.active_packet_no(), Some(1));

    app.worklist
        .restored_packet_scopes
        .insert(2, "different-capture".into());
    assert!(app.scope_dns_exchange(1, mixed).unwrap().replies.is_empty());
}

fn tcp_frame(no: u64, sequence: u32, flags: u8, response: bool, payload: &[u8]) -> Packet {
    let base = dns_frame(no, [10, 0, 0, 53], response);
    let mut raw = base.bytes[..38].to_vec();
    raw.resize(54, 0);
    raw[16..18].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    raw[23] = 6;
    raw[38..42].copy_from_slice(&sequence.to_be_bytes());
    raw[46] = 0x50;
    raw[47] = flags;
    raw.extend(payload);
    crate::net::parser::parse_ethernet(&raw, no, no as f64)
}

fn two_dns_messages(response: bool) -> Vec<u8> {
    let base = dns_frame(1, [10, 0, 0, 53], response);
    let mut message = base.bytes[42..].to_vec();
    let size = (message.len() as u16).to_be_bytes();
    let mut data = size.to_vec();
    data.extend_from_slice(&message);
    message[1] += 1;
    data.extend(size);
    data.extend(&message);
    data
}

#[test]
fn offline_case_rebuilds_stream_and_dns_context_without_crossing_capture_scopes() {
    use crate::model::project::{ProjectSaveMode, ProjectState, SavedInvestigationItem};
    use ratatui::{Terminal, backend::TestBackend};

    let query = tcp_frame(3, 101, 0x18, false, &two_dns_messages(false));
    let reply = tcp_frame(4, 201, 0x18, true, &two_dns_messages(true));
    let packets = [
        reply.clone(),
        tcp_frame(1, 100, 0x02, false, &[]),
        query.clone(),
        tcp_frame(2, 200, 0x12, true, &[]),
        tcp_frame(5, 250, 0x10, false, &[]),
    ];
    let scope = "saved-capture";
    for second_scope in [Some(scope), Some("different-capture"), None] {
        let complete_scope = second_scope == Some(scope);
        let mut state = ProjectState::new("Saved DNS case", ProjectSaveMode::Lightweight);
        state.pinned_packets = packets.to_vec();
        state.investigation_items = (1..=5).map(SavedInvestigationItem::Packet).collect();
        state.active_investigation = Some(3);
        state.investigation_tray_open = true;
        state.active_tab = Tab::Investigate.index();
        for frame in [1, 2, 4, 5] { state.pinned_packet_scopes.insert(frame, scope.into()); }
        if let Some(other) = second_scope { state.pinned_packet_scopes.insert(3, other.into()); }
        let mut alerts = crate::analysis::alert_center::AlertCenter::default();
        alerts.capture_id = Some(scope.into());
        alerts.record(4, "IDS", "HIGH", "Saved finding", "fixture");
        state.alert_items = alerts.items;
        let (tx, _) = tokio::sync::mpsc::channel(1);
        let mut app = App::new_with_mode(tx, StartupMode::OfflineReview);
        app.apply_project_state(state).unwrap();
        app.inject_packet(tcp_frame(5, 250, 0x18, false, &[]));
        app.load_pcap_instant("must-not-be-opened.pcapng");
        assert!(app.status_msg.as_deref().unwrap().contains("preserve offline review evidence scope"));
        assert_eq!(app.active_investigation_packet().unwrap().no, 4);
        assert!(app.packets.is_empty());
        assert_eq!(app.active_investigation_stream().is_some(), complete_scope);
        app.query_core(|core| {
            assert_eq!(app.dns_exchanges(core, &reply).len(), if complete_scope { 2 } else { 0 });
            assert_eq!(core.alert_center.items.len(), 1);
            assert_eq!(core.alert_center.items[0].title, "Saved finding");
            assert!(core.security.ids_alerts.is_empty());
            assert!(core.incidents.incidents.is_empty());
        }).unwrap();
        if complete_scope {
            let mut terminal = Terminal::new(TestBackend::new(110, 28)).unwrap();
            terminal.draw(|frame| crate::ui::draw(frame, &app)).unwrap();
            let rendered = terminal.backend().to_string();
            assert!(rendered.contains("offline review"));
            assert!(rendered.contains("5 retained frames"));
            assert!(rendered.contains("Retained evidence subset | Capture: saved-capture"));
            app.worklist_next_packet();
            assert_eq!(app.active_investigation_packet().unwrap().no, 5);
            assert!(app.active_investigation_stream().is_none());
            app.open_active_investigation_stream_overlay();
            assert!(app.stream_overlay.is_none());
        }
    }
}

#[test]
fn coalesced_dns_evidence_keeps_the_keyboard_selected_transaction() {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Investigate;
    app.investigation_view = InvestigationView::Transactions;
    let query = tcp_frame(3, 101, 0x18, false, &two_dns_messages(false));
    let reply = tcp_frame(4, 201, 0x18, true, &two_dns_messages(true));
    for packet in [
        tcp_frame(1, 100, 0x02, false, &[]),
        tcp_frame(2, 200, 0x12, true, &[]),
        query.clone(),
        reply.clone(),
    ] {
        app.core.edit().analyze(&packet);
        app.packets.push_back(packet);
    }
    let selected = |app: &App| {
        let packet = app.active_investigation_packet().unwrap();
        app.query_core(|core| {
            let exchanges = app.dns_exchanges(core, packet);
            assert_eq!(exchanges.len(), 2);
            exchanges[app.dns_exchange_index(&exchanges)].transaction_id
        })
        .unwrap()
    };
    let arrow = |app: &mut App, code| {
        crate::event::handle(app, Event::Key(KeyEvent::new(code, KeyModifiers::NONE)));
    };
    app.worklist.pin_packet(&reply).unwrap();
    assert_eq!(selected(&app), 42);
    arrow(&mut app, KeyCode::Left);
    assert_eq!(selected(&app), 43);
    advance(&mut app);
    assert_eq!(app.worklist.active_packet_no(), Some(3));
    assert_eq!(selected(&app), 43);
    arrow(&mut app, KeyCode::Right);
    assert_eq!(selected(&app), 42);
    advance(&mut app);
    assert_eq!(app.worklist.active_packet_no(), Some(4));
    assert_eq!(selected(&app), 42);
}

#[test]
fn offline_case_does_not_reconstruct_dns_from_conflicting_tcp_overlaps() {
    use crate::model::project::{ProjectSaveMode, ProjectState, SavedInvestigationItem};

    let query = two_dns_messages(false);
    let reply = tcp_frame(6, 201, 0x18, true, &two_dns_messages(true));
    let scope = "saved-capture";
    for conflicting in [false, true] {
        let mut overlap = query[4..8].to_vec();
        if conflicting {
            overlap[0] ^= 1;
        }
        let mut state = ProjectState::new("Saved DNS case", ProjectSaveMode::Lightweight);
        state.pinned_packets = vec![
            tcp_frame(1, 100, 0x02, false, &[]),
            tcp_frame(2, 200, 0x12, true, &[]),
            tcp_frame(3, 101, 0x18, false, &query[..8]),
            tcp_frame(4, 105, 0x18, false, &overlap),
            tcp_frame(5, 109, 0x18, false, &query[8..]),
            reply.clone(),
        ];
        state.pinned_packet_scopes = (1..=6).map(|frame| (frame, scope.into())).collect();
        state.investigation_items = (1..=6).map(SavedInvestigationItem::Packet).collect();
        let mut alerts = crate::analysis::alert_center::AlertCenter::default();
        alerts.capture_id = Some(scope.into());
        alerts.record(6, "IDS", "HIGH", "Saved finding", "fixture");
        state.alert_items = alerts.items;
        let (tx, _) = tokio::sync::mpsc::channel(1);
        let mut app = App::new_with_mode(tx, StartupMode::OfflineReview);
        app.apply_project_state(state).unwrap();
        app.query_core(|core| {
            let exchanges = app.dns_exchanges(core, &reply);
            assert_eq!(exchanges.len(), if conflicting { 0 } else { 2 });
            if !conflicting {
                assert!(exchanges.iter().any(|exchange| exchange.query_frames == [3, 5]));
                assert!(exchanges.iter().all(|exchange| !exchange.query_frames.contains(&4)));
            }
            assert_eq!(core.alert_center.items.len(), 1);
            assert!(core.security.ids_alerts.is_empty());
        }).unwrap();
    }
}
