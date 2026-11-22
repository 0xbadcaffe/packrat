use super::*;
use crate::engine::PacketAnalysis;

#[test]
fn selective_archive_retains_scoped_high_alert_frames_without_pinning_unrelated_traffic() {
    use crate::storage::packet_archive::{ArchiveLimits, ArchiveWorker, PacketArchive};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("archive");
    let mut app = App::new_for_test();
    app.set_packet_archive(ArchiveWorker::open_alert_evidence(&path, ArchiveLimits::default()).unwrap()).unwrap();
    let scope = app.capture_id.clone().unwrap();
    for frame in 1..=4 {
        app.inject_packet(packet(frame));
    }
    for (trigger, severity, key) in [(2, "HIGH", "first"), (3, "MEDIUM", "ignored"), (4, "CRITICAL", "second")] {
        let analysis = {
            let mut core = app.core.edit();
            core.alert_center.automation_mode = AutomationMode::Off;
            core.alert_center.record_correlated_with_evidence(
                (trigger, &[1]), trigger as f64, "TEST", severity, key, "observation", key,
            );
            PacketAnalysis { alert_pins: core.alert_center.drain_pending_pins(), ..Default::default() }
        };
        let context = app.analysis_context(&analysis).unwrap();
        app.handle_packet_analysis(analysis, context, false, false, None);
    }
    assert!(app.worklist.items.is_empty());
    app.packet_archive.as_mut().unwrap().finish().unwrap();
    let mut reader = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(reader.count().unwrap(), 3);
    assert!(reader.packet_for_capture(&scope, 3).unwrap().is_none());
    for n in [1, 2, 4] {
        assert_eq!(reader.packet_for_capture(&scope, n).unwrap().unwrap().no, n);
    }
}

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

    let follow_up = packet(30);
    let pins = {
        let mut core = app.core.edit();
        core.alert_center.record_correlated(
            30,
            3.0,
            "IDS",
            "HIGH",
            "Finding",
            "follow-up observation",
            "flow-a",
        );
        core.alert_center.drain_pending_pins()
    };
    let update = PacketAnalysis {
        alert_pins: pins,
        ..Default::default()
    };
    let context = app.analysis_context(&update).unwrap();
    app.handle_packet_analysis(update, context, false, false, Some(&follow_up));
    assert_eq!(app.worklist.active_packet_no(), Some(9));
    assert_eq!(
        app.worklist.retained_packet(30).unwrap().bytes,
        follow_up.bytes
    );
    assert!(app.worklist.retained_packet(20).is_some());
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
