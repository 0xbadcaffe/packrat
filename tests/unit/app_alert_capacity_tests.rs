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
