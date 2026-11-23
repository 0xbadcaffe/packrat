use super::*;
use crate::net::parser::parse_ethernet;

#[test]
fn investigating_an_alert_reserves_the_last_pin_for_the_trigger() {
    let mut app = App::new_for_test();
    for frame in 100..100 + InvestigationTray::MAX_RETAINED_PACKETS as u64 - 1 {
        app.worklist.pin_packet(&parse_ethernet(&[], frame, frame as f64)).unwrap();
    }
    app.packets.extend([
        parse_ethernet(&[], 10, 1.0),
        parse_ethernet(&[], 20, 2.0),
    ]);
    app.core.edit().alert_center.record_correlated_with_evidence(
        (20, &[10]), 2.0, "IDS", "HIGH", "Finding", "Two frames", "flow-a",
    );

    assert!(app.investigate_selected_alert());
    assert_eq!(app.worklist.active_packet_no(), Some(20));
    assert!(app.worklist.retained_packet(20).is_some());
    assert!(app.worklist.retained_packet(10).is_none());
    assert!(app.worklist.retained_packet(100).is_some());
    assert!(app.status_msg.as_deref().unwrap().contains("1 unavailable (1 hit the tray limit)"));
}

#[test]
fn alert_resolution_preserves_pin_precedence_in_a_full_buffer_and_keeps_missing_refs() {
    let mut app = App::new_for_test();
    let capture = App::new_capture_id();
    app.capture_id = Some(capture.clone());
    app.restored_project_max_frame = 2;
    app.packets.extend((1..=10_000).rev().map(|frame| parse_ethernet(&[], frame, frame as f64)));
    let mut pin = parse_ethernet(&[], 5_000, 5_000.0);
    pin.info = "Already pinned".into();
    app.worklist.pin_packet(&pin).unwrap();
    let alert = {
        let mut core = app.core.edit();
        core.alert_center.capture_id = Some(capture.to_string());
        core.alert_center.record_correlated_with_evidence(
            (9_999, &[1, 3, 5_000, 10_001]), 9_999.0, "IDS", "HIGH", "Finding", "Scoped frames", "flow",
        );
        core.alert_center.items[0].clone()
    };
    assert_eq!(app.alert_evidence_status(&alert), "3/5 retained; 3 capture lengths unknown; 2 unavailable");
    assert!(app.investigate_selected_alert());
    assert_eq!(app.worklist.active_packet_no(), Some(9_999));
    assert_eq!(app.worklist.packet_nos(), [5_000, 3, 9_999]);
    assert_eq!(app.worklist.retained_packet(5_000).unwrap().info, "Already pinned");
    assert!(app.status_msg.as_deref().unwrap().contains("2 unavailable"));
}
