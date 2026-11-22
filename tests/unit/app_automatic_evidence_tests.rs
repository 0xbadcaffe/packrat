use super::*;
use crate::engine::PacketAnalysis;

#[test]
fn watch_preserves_trigger_and_prior_evidence_without_stealing_selection() {
    let mut app = App::new_for_test();
    app.packets.push_back(packet(10));
    app.worklist.pin_packet(&packet(9)).unwrap();
    let trigger = packet(20);
    let pins = {
        let mut core = app.core.edit();
        core.alert_center.automation_mode = AutomationMode::Watch;
        core.alert_center.record_correlated_with_evidence(
            (20, &[10, 11]),
            2.0,
            "IDS",
            "HIGH",
            "Finding",
            "observation",
            "flow-a",
        );
        core.alert_center.drain_pending_pins()
    };
    let analysis = PacketAnalysis {
        alert_pins: pins,
        ..Default::default()
    };
    let context = app.analysis_context(&analysis).unwrap();
    app.handle_packet_analysis(analysis, context, false, false, Some(&trigger));
    app.packets.clear();

    assert_eq!(app.worklist.active_packet_no(), Some(9));
    assert!(app.worklist.items.contains(&InvestigationItem::Alert(1)));
    assert!(app.worklist.retained_packet(10).is_some());
    assert!(app.worklist.retained_packet(11).is_none());
    assert_eq!(
        app.worklist.retained_packet(20).unwrap().bytes,
        trigger.bytes
    );
    assert!(app.project_dirty);
    assert!(!app.worklist.open);
}

#[test]
fn watch_does_not_retain_packets_from_an_unverified_capture() {
    let mut app = App::new_for_test();
    app.capture_id = Some(App::new_capture_id());
    let pins = {
        let mut core = app.core.edit();
        core.alert_center.automation_mode = AutomationMode::Watch;
        core.alert_center
            .record(20, "IDS", "HIGH", "Unscoped finding", "observation");
        core.alert_center.drain_pending_pins()
    };
    let analysis = PacketAnalysis {
        alert_pins: pins,
        ..Default::default()
    };
    let context = app.analysis_context(&analysis).unwrap();
    app.handle_packet_analysis(analysis, context, false, false, Some(&packet(20)));
    assert!(app.worklist.items.is_empty());
    assert!(!app.project_dirty);
}
