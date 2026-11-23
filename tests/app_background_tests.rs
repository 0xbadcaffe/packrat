#![cfg(feature = "terminal-ui")]
#[path = "support/packets.rs"]
mod packets;
#[path = "support/critical.rs"]
mod critical;
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
fn opted_in_tcp_reset_evidence_survives_rollover_and_remains_vlan_scoped() {
    use packrat_tui::engine::worker::WorkerLimits;
    use packrat_tui::net::parser::parse_ethernet;
    use packrat_tui::storage::packet_archive::{ArchiveLimits, ArchiveWorker, PacketArchive};

    let tagged = |packet: packrat_tui::net::packet::Packet, vlan: u16, reverse: bool, time| {
        let mut bytes = packet.bytes;
        if reverse {
            for index in 0..4 { bytes.swap(26 + index, 30 + index); }
            for index in 0..2 { bytes.swap(34 + index, 36 + index); }
        }
        bytes.splice(12..12, [0x81, 0, 0, vlan as u8]);
        parse_ethernet(&bytes, packet.no, time)
    };
    let rule = "tcp.payload_after_observed_reset";
    for selected in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("archive");
        let mut app = App::new_for_test();
        let archive = ArchiveWorker::open_alert_evidence(&path, ArchiveLimits::default()).unwrap();
        app.set_packet_archive_with_rules(archive, selected.then(|| rule.to_owned()).into_iter().collect()).unwrap();
        app.start_background_analysis().unwrap();
        let reset = tagged(packets::tcp(1, 100, 0x04, b""), 10, false, 1.0);
        app.inject_packet(reset.clone());
        app.inject_packet(tagged(packets::tcp(2, 123, 0x04, b""), 20, false, 2.0));
        drain(&mut app);
        let peer = WorkerLimits::default().history_packets as u64 + 4;
        for no in 3..peer {
            app.inject_packet(parse_ethernet(&[0; 14], no, 2.0));
            drain(&mut app);
        }
        app.packets.clear();
        app.inject_packet(tagged(packets::tcp(peer, 200, 0x18, b"peer data"), 10, true, 3.0));
        drain(&mut app);
        app.inject_packet(tagged(packets::tcp(peer + 1, 101, 0x18, b"same sender"), 10, false, 4.0));
        drain(&mut app);
        app.stop_background_analysis().unwrap();
        app.packet_archive.as_mut().unwrap().finish().unwrap();

        let alert = app.query_core(|core| core.alert_center.items.iter().find(|alert|
            alert.provenance.as_ref().is_some_and(|provenance| provenance.rule_id == rule)).cloned()).unwrap().unwrap();
        assert_eq!(alert.packet_refs, [1, peer, peer + 1]);
        assert_eq!(alert.hit_count, 2);
        let scope = alert.capture_id.unwrap();
        let mut archive = PacketArchive::open_readonly(&path).unwrap();
        assert_eq!(archive.count().unwrap(), if selected { 3 } else { 0 });
        assert!(archive.packet_for_capture(&scope, 2).unwrap().is_none());
        let saved = archive.packet_for_capture(&scope, 1).unwrap();
        assert_eq!(saved.map(|packet| packet.bytes), selected.then_some(reset.bytes));
        for frame in [peer, peer + 1] {
            assert_eq!(archive.packet_for_capture(&scope, frame).unwrap().is_some(), selected);
        }
    }
}

#[test]
fn periodic_archive_retains_only_the_matched_run_after_worker_history_rolls_over() {
    use packrat_tui::engine::worker::WorkerLimits;
    use packrat_tui::net::parser::parse_ethernet;
    use packrat_tui::storage::packet_archive::{ArchiveLimits, ArchiveWorker, PacketArchive};

    let rule = "traffic.periodic_fixed_size";
    let sample = |no, timestamp, size| {
        let mut pkt = packets::tcp(no, no as u32 * 1000, 0x18, &vec![1; size]);
        pkt.timestamp = timestamp;
        pkt
    };
    for selected in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("archive");
        let mut app = App::new_for_test();
        let archive = ArchiveWorker::open_alert_evidence(&path, ArchiveLimits::default()).unwrap();
        app.set_packet_archive_with_rules(archive, selected.then(|| rule.to_owned()).into_iter().collect()).unwrap();
        app.start_background_analysis().unwrap();
        for (index, time) in [1.0, 2.0, 4.0, 15.0].into_iter().enumerate() {
            app.inject_packet(sample(index as u64 + 1, time, 400));
        }
        for frame in 5..=10 {
            app.inject_packet(sample(frame, 60.0 + (frame - 5) as f64 * 10.0, 70));
        }
        drain(&mut app);
        let trigger = WorkerLimits::default().history_packets as u64 + 12;
        for no in 11..trigger {
            app.inject_packet(parse_ethernet(&[0; 14], no, 115.0));
            drain(&mut app);
        }
        app.packets.clear();
        app.inject_packet(sample(trigger, 120.0, 70));
        drain(&mut app);
        app.stop_background_analysis().unwrap();
        app.packet_archive.as_mut().unwrap().finish().unwrap();

        let alert = app.query_core(|core| core.alert_center.items.iter().find(|alert|
            alert.provenance.as_ref().is_some_and(|provenance| provenance.rule_id == rule)).cloned()).unwrap().unwrap();
        let expected = (5..=10).chain([trigger]).collect::<Vec<_>>();
        assert_eq!(alert.packet_refs, expected);
        assert_eq!(alert.severity, "MEDIUM");
        let scope = alert.capture_id.unwrap();
        let mut archive = PacketArchive::open_readonly(&path).unwrap();
        assert_eq!(archive.count().unwrap(), if selected { 7 } else { 0 });
        for frame in expected {
            assert_eq!(archive.packet_for_capture(&scope, frame).unwrap().is_some(), selected);
        }
        for frame in 1..5 {
            assert!(archive.packet_for_capture(&scope, frame).unwrap().is_none());
        }
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
    app.inject_packet(critical::http_framing_ambiguity(1));
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
    app.inject_packet(critical::http_framing_ambiguity(1));
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

#[tokio::test]
async fn live_dispatch_resumes_on_worker_events_without_a_ui_tick() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
    let mut app = App::new(tx.clone());
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
    app.tick();
    let pressure = app.telemetry.snapshot().capture_queue;
    assert_eq!(pressure.capacity, 1024);
    assert_eq!(pressure.depth, rx.len());
    assert!(pressure.dispatch_waiting && pressure.analysis_packets_pending > 0);
    let ready = app.analysis_event_notifier().unwrap();
    release.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !rx.is_empty() || pending.is_some() || !app.analysis_idle() {
        app.poll_analysis();
        app.dispatch_capture(&mut rx, &mut pending).unwrap();
        assert!(Instant::now() < deadline);
        if pending.is_some() || (rx.is_empty() && !app.analysis_idle()) {
            tokio::time::timeout_at(deadline.into(), ready.notified())
                .await
                .expect("capture stalled waiting for the analysis worker");
        }
    }
    assert_eq!(app.packets.len(), 600);
    assert_eq!(
        app.packets.iter().map(|p| p.no).collect::<Vec<_>>(),
        (1..=600).collect::<Vec<_>>()
    );
    app.tick();
    let drained = app.telemetry.snapshot().capture_queue;
    assert_eq!(drained.depth, 0);
    assert_eq!(drained.analysis_packets_pending, 0);
    assert!(!drained.dispatch_waiting);
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
