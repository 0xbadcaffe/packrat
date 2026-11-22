use super::*;

#[path = "app_saved_case_evidence_tests.rs"]
mod saved_case_evidence;
#[path = "app_automatic_evidence_tests.rs"]
mod automatic_evidence;

#[test]
fn background_restore_preserves_acknowledgements_without_reopening_alerts() {
    let mut source = App::new_for_test();
    source.inject_packet(packet(1));
    source.open_user_rule_incident(&packet(1), "rule", "rule", "finding", false);
    source.open_active_incident_analysis();
    source.acknowledge_active_incident().unwrap();
    let state = source
        .snapshot_project("case", ProjectSaveMode::Portable)
        .unwrap();
    let mut restored = App::new_for_test();
    restored.start_background_analysis().unwrap();
    restored.apply_project_state(state).unwrap();
    assert!(
        restored
            .snapshot_project("pending", ProjectSaveMode::Portable)
            .is_err()
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !restored.analysis_idle() {
        restored.poll_analysis();
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert!(!restored.alert_overlay_open);
    assert_eq!(restored.packets.len(), 1);
    assert_eq!(
        restored.query_core(|core| core.incidents.active().is_none()),
        Some(true)
    );
    assert_eq!(
        restored.query_core(|core| core.incidents.incidents[0].reviewed),
        Some(true)
    );
    assert!(restored.evidence_vault.exports.is_empty());
    assert!(restored.traffic_latch.actions.is_empty());
}

fn packet(no: u64) -> Packet {
    Packet {
        capture: None,
        no,
        timestamp: 1.0,
        src: "192.0.2.1".into(),
        dst: "198.51.100.2".into(),
        protocol: "UDP".into(),
        length: 4,
        info: "project test".into(),
        src_port: Some(50000),
        dst_port: Some(53),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes: vec![1, 2, 3, 4],
    }
}

#[test]
fn portable_snapshot_embeds_packets_but_lightweight_does_not() {
    let mut app = App::new_for_test();
    app.inject_packet(packet(1));

    let portable = app
        .snapshot_project("portable", ProjectSaveMode::Portable)
        .unwrap();
    assert_eq!(portable.embedded_packets.len(), 1);
    assert_eq!(portable.embedded_packets[0].bytes, vec![1, 2, 3, 4]);
    let lightweight = app
        .snapshot_project("light", ProjectSaveMode::Lightweight)
        .unwrap();
    assert!(lightweight.embedded_packets.is_empty());
}

#[test]
fn pinned_packet_survives_live_eviction_and_both_project_modes() {
    let mut app = App::new_for_test();
    app.retain_packet_display(packet(1));
    app.mark_selected_packet_for_investigation();
    for no in 2..=MAX_PACKETS as u64 + 1 {
        app.retain_packet_display(packet(no));
    }
    assert!(app.packets.iter().all(|packet| packet.no != 1));
    assert_eq!(
        app.active_investigation_packet().unwrap().bytes,
        [1, 2, 3, 4]
    );
    for mode in [ProjectSaveMode::Lightweight, ProjectSaveMode::Portable] {
        let state = app.snapshot_project("retained", mode).unwrap();
        let serialized = serde_json::to_vec(&state).unwrap();
        let restored = serde_json::from_slice(&serialized).unwrap();
        let tray = restore_investigation_tray(&restored).unwrap();
        assert_eq!(tray.active_packet_no(), Some(1));
        assert_eq!(tray.retained_packet(1).unwrap().bytes, [1, 2, 3, 4]);
    }
    app.remove_active_worklist_packet();
    assert!(app.packet_by_no(1).is_none());
    assert_eq!(app.worklist.retained_bytes, 0);
}

#[test]
fn investigating_alert_pins_matching_packets_and_opens_workspace() {
    let mut app = App::new_for_test();
    app.packets.extend([packet(10), packet(20), packet(30)]);
    app.core.edit().alert_center.record_correlated(
        10,
        1.0,
        "IDS",
        "HIGH",
        "Beacon",
        "periodic traffic",
        "192.0.2.1>198.51.100.2",
    );
    app.core.edit().alert_center.record_correlated(
        30,
        3.0,
        "IDS",
        "HIGH",
        "Beacon",
        "periodic traffic",
        "192.0.2.1>198.51.100.2",
    );

    assert!(app.investigate_selected_alert());
    assert_eq!(app.active_tab, Tab::Investigate);
    assert_eq!(app.worklist.packet_nos(), vec![10, 30]);
    assert_eq!(app.worklist.active_packet_no(), Some(30));
    assert!(app.worklist.items.contains(&InvestigationItem::Alert(1)));
    assert!(app.worklist.retained_packet(10).is_some());
    assert!(app.worklist.retained_packet(30).is_some());
}

#[test]
fn alert_investigation_reports_packet_refs_missing_from_retention() {
    let mut app = App::new_for_test();
    app.packets.push_back(packet(20));
    app.core.edit().alert_center.record_correlated(
        10,
        1.0,
        "IDS",
        "HIGH",
        "Beacon",
        "periodic traffic",
        "flow-a",
    );
    app.core.edit().alert_center.record_correlated(
        20,
        2.0,
        "IDS",
        "HIGH",
        "Beacon",
        "periodic traffic",
        "flow-a",
    );

    assert!(app.investigate_selected_alert());
    assert_eq!(app.worklist.packet_nos(), vec![20]);
    assert!(app.status_msg.as_deref().unwrap().contains("1 unavailable"));
}

#[test]
fn alert_evidence_preview_distinguishes_truncated_pins_and_missing_frames() {
    use crate::net::packet::CaptureMetadata;

    let mut app = App::new_for_test();
    app.packets.extend([packet(10), packet(20)]);
    let mut partial = packet(10);
    partial.capture = Some(CaptureMetadata {
        timestamp: None,
        captured_length: 4,
        wire_length: 60,
        link_type: 1,
        interface_id: 0,
        section_id: 0,
        interface_name: None,
        comments: Vec::new(),
    });
    app.worklist.pin_packet(&partial).unwrap();
    let mut core = app.core.edit();
    core.alert_center.record(10, "IDS", "HIGH", "Evidence", "mixed capture");
    let alert = &mut core.alert_center.items[0];
    alert.packet_refs = vec![10, 10, 20, 30];
    assert_eq!(app.alert_evidence_status(alert), "2/3 retained; 1 truncated; 1 unavailable; capture ID not recorded");
}

#[test]
fn unscoped_alert_does_not_open_overlapping_live_or_pinned_frames() {
    let mut app = App::new_for_test();
    app.capture_id = Some(App::new_capture_id());
    app.packets.extend([packet(10), packet(11)]);
    app.worklist.pin_packet(&packet(10)).unwrap();
    let alert = {
        let mut core = app.core.edit();
        core.alert_center.record(10, "IDS", "HIGH", "Legacy alert", "missing capture ID");
        core.alert_center.items[0].packet_refs = vec![10, 11];
        core.alert_center.items[0].clone()
    };

    assert!(alert.capture_id.is_none());
    assert_eq!(
        app.alert_evidence_status(&alert),
        "0/2 verified here; capture ID not recorded"
    );
    assert!(app.investigate_selected_alert());
    assert_eq!(app.worklist.packet_nos(), [10]);
    assert_eq!(app.worklist.active_packet_no(), None);
    assert!(app.status_msg.as_deref().unwrap().contains("2 unavailable (capture ID not recorded)"));
}

#[test]
fn alert_investigation_recovers_archived_frames_without_crossing_captures() {
    use crate::storage::packet_archive::{ArchiveWorker, PacketArchive};

    let directory = tempfile::tempdir().unwrap();
    let archive = directory.path().join("archive");
    let mut app = App::new_for_test();
    app.set_packet_archive(ArchiveWorker::open(&archive).unwrap()).unwrap();
    let capture_a = app.capture_id.clone().unwrap();
    let mut first = packet(90);
    first.info = "first capture".into();
    app.inject_packet(first);
    app.inject_packet(packet(90));
    assert_eq!(app.packets.iter().map(|packet| packet.no).collect::<Vec<_>>(), [1, 2]);
    {
        let mut core = app.core.edit();
        core.alert_center.record(1, "IDS", "HIGH", "Evidence", "first capture");
        core.alert_center.record(2, "IDS", "HIGH", "Evidence", "first capture");
        assert_eq!(core.alert_center.items[0].capture_id.as_deref(), Some(capture_a.as_ref()));
    }
    let old_alerts = app.core.edit().alert_center.items.clone();
    app.packets.clear();
    assert_eq!(app.alert_evidence_status(&old_alerts[0]), "0/2 retained; 2 unchecked in archive");
    app.packet_archive.as_mut().unwrap().finish().unwrap();
    assert!(app.investigate_selected_alert());
    assert_eq!(app.worklist.packet_nos(), [1, 2]);
    assert_eq!(app.worklist.retained_packet(1).unwrap().info, "first capture");
    assert_eq!(app.alert_evidence_status(&old_alerts[0]), "2/2 retained");
    assert!(app.status_msg.as_deref().unwrap().contains("2 archived"));

    app.try_clear_packets().unwrap();
    let capture_b = app.capture_id.clone().unwrap();
    assert_ne!(capture_a, capture_b);
    assert_eq!(app.alert_evidence_status(&old_alerts[0]), "0/2 verified here; different capture");
    app.packet_archive = Some(ArchiveWorker::open(&archive).unwrap());
    let mut second = packet(90);
    second.info = "second capture".into();
    app.inject_packet(second);
    app.core.edit().alert_center.restore(old_alerts, AutomationMode::Off);
    assert!(app.investigate_selected_alert());
    assert!(app.worklist.packet_nos().is_empty());
    assert!(app.status_msg.as_deref().unwrap().contains("2 unavailable"));

    app.packet_archive.as_mut().unwrap().finish().unwrap();
    let mut reader = PacketArchive::open_readonly(&archive).unwrap();
    assert_eq!(reader.packet_for_capture(&capture_a, 1).unwrap().unwrap().info, "first capture");
    assert_eq!(reader.packet_for_capture(&capture_b, 1).unwrap().unwrap().info, "second capture");
}

#[test]
fn background_clear_updates_capture_scope_before_subsequent_findings() {
    use crate::storage::packet_archive::ArchiveWorker;

    let directory = tempfile::tempdir().unwrap();
    let mut app = App::new_for_test();
    app.set_packet_archive(ArchiveWorker::open(&directory.path().join("archive")).unwrap()).unwrap();
    let old = app.capture_id.clone();
    app.start_background_analysis().unwrap();
    app.try_clear_packets().unwrap();
    let current = app.capture_id.clone().unwrap();
    assert_ne!(old.as_deref(), Some(current.as_ref()));
    app.inject_packet(packet(7));
    app.configure_core(|core| {
        core.alert_center.record(1, "IDS", "HIGH", "Evidence", "new generation");
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !app.analysis_idle() {
        app.poll_analysis();
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    let observed = app.query_core(|core| core.alert_center.items[0].capture_id.clone());
    assert_eq!(observed.flatten().as_deref(), Some(current.as_ref()));
    assert_eq!(app.packets[0].no, 1);
}

#[tokio::test]
async fn live_capture_scope_is_recorded_without_archiving_and_switches_queue() {
    let (original_tx, mut original_rx) = tokio::sync::mpsc::channel(64);
    let mut app = App::new(original_tx.clone());
    app.iface_list = vec!["simulated".into()];
    original_tx.try_send(packet(99)).unwrap();
    app.confirm_iface();
    assert!(app.capturing);
    assert!(app.packet_archive.is_none());
    let scope = app.capture_id.clone().unwrap();
    let mut live_rx = app.take_capture_receiver().unwrap();
    assert_eq!(original_rx.try_recv().unwrap().no, 99);
    let first = tokio::time::timeout(std::time::Duration::from_secs(1), live_rx.recv()).await.unwrap().unwrap();
    assert_ne!(first.no, 99);
    let before = app.capture_frame_high_water;
    app.ingest_packet(first);
    let observed = app.capture_frame_high_water;
    assert_eq!(observed, before + 1);
    app.core.edit().alert_center.record(observed, "IDS", "LOW", "Scope test", "Observed frame");
    let alert_scope = app.query_core(|core| {
        core.alert_center.items.iter().find(|alert| alert.title == "Scope test")
            .and_then(|alert| alert.capture_id.clone())
    }).flatten();
    assert_eq!(alert_scope.as_deref(), Some(scope.as_ref()));
    app.refresh_telemetry();
    assert_eq!(app.telemetry.snapshot().capture_id.as_deref(), Some(scope.as_ref()));
    assert_eq!(app.telemetry.snapshot().alert_session_id.as_deref(), Some(app.alert_session_id.as_ref()));

    app.confirm_iface();
    assert_ne!(app.capture_id.as_deref(), Some(scope.as_ref()));
    assert!(app.take_capture_receiver().is_some());
    app.abort_capture();
}

#[test]
fn capture_keeps_running_after_the_archive_frame_limit() {
    use crate::storage::packet_archive::{ArchiveLimits, ArchiveWorker, PacketArchive};

    let directory = tempfile::tempdir().unwrap();
    let archive = directory.path().join("archive");
    let limits = ArchiveLimits {
        max_frames: 1,
        reserve_free_bytes: 0,
        ..ArchiveLimits::default()
    };
    let mut app = App::new_for_test();
    app.set_packet_archive(ArchiveWorker::open_with_limits(&archive, limits).unwrap())
        .unwrap();
    app.capturing = true;
    app.ingest_packet(packet(10));
    app.packet_archive.as_mut().unwrap().finish().unwrap();
    app.tick();
    assert!(app.capturing);
    assert!(app.status_msg.as_deref().unwrap().contains("Archive paused"));
    app.ingest_packet(packet(11));
    assert!(app.capturing);
    assert_eq!(app.packets.len(), 2);
    assert_eq!(PacketArchive::open_readonly(&archive).unwrap().count().unwrap(), 1);
}

#[test]
fn pin_limits_fail_without_losing_or_silently_evicting_evidence() {
    let mut tray = InvestigationTray::default();
    for no in 0..InvestigationTray::MAX_RETAINED_PACKETS as u64 {
        assert!(tray.pin_packet(&packet(no)).unwrap());
    }
    let used = tray.retained_bytes;
    assert!(!tray.pin_packet(&packet(0)).unwrap());
    assert_eq!(tray.retained_bytes, used);
    assert!(tray.pin_packet(&packet(2048)).is_err());
    assert!(tray.retained_packet(0).is_some());
    tray.remove_active();
    assert!(tray.pin_packet(&packet(2048)).unwrap());

    let mut full = InvestigationTray::default();
    full.retained_bytes = InvestigationTray::MAX_RETAINED_BYTES;
    assert!(full.pin_packet(&packet(1)).is_err());
    assert!(full.items.is_empty());
}

#[test]
fn legacy_portable_projects_restore_pins_before_live_ring_eviction() {
    let mut state = crate::model::project::ProjectState::new("old", ProjectSaveMode::Portable);
    state.investigation_items = vec![SavedInvestigationItem::Packet(1)];
    state.active_investigation = Some(0);
    state.embedded_packets = vec![packet(1), packet(2)];
    let tray = restore_investigation_tray(&state).unwrap();
    assert_eq!(tray.retained_packet(1).unwrap().no, 1);
    assert!(tray.retained_packet(2).is_none());
}

#[test]
fn explicit_auto_contain_rule_cannot_enforce_an_offline_incident() {
    let mut app = App::new_for_test();
    app.traffic_latch.mode = LatchMode::Automatic;
    app.latch_helper_path = Some("/must-not-execute".into());
    app.inject_packet(packet(1));
    app.open_user_rule_incident(&packet(1), "auto-rule", "auto", "test", true);
    assert_eq!(app.traffic_latch.actions.len(), 1);
    assert_eq!(
        app.traffic_latch.actions[0].status,
        crate::analysis::traffic_latch::LatchStatus::Observed
    );
    app.approve_active_latch();
    assert_eq!(
        app.traffic_latch.actions[0].status,
        crate::analysis::traffic_latch::LatchStatus::Observed
    );
}

#[test]
fn cases_restore_reviewed_incidents_and_correlated_impact_without_side_effects() {
    use crate::analysis::impact::{EndpointCategory, EndpointEvidence, ImpactConfidence};
    let mut source = App::new_for_test();
    source.inject_packet(packet(1));
    source.open_user_rule_incident(&packet(1), "rule", "rule", "finding", true);
    let id = source.core.edit().incidents.active().unwrap().id;
    source.core.edit().incidents.mark_active_reviewed();
    source.core.edit().incidents.acknowledge_active().unwrap();
    source.core.edit().endpoint_evidence.push(EndpointEvidence {
        incident_id: id,
        target: "198.51.100.2".into(),
        source: "audit".into(),
        evidence_id: "event-17".into(),
        category: EndpointCategory::File,
        subject: "/srv/private.csv".into(),
        action: "read".into(),
        successful: true,
    });

    for mode in [ProjectSaveMode::Lightweight, ProjectSaveMode::Portable] {
        let state = source.snapshot_project("case", mode).unwrap();
        let json = serde_json::to_vec(&state).unwrap();
        let directory =
            std::env::temp_dir().join(format!("packrat-restore-{}", rand::random::<u64>()));
        let mut restored = App::new_for_test();
        restored.packet_archive =
            Some(crate::storage::packet_archive::ArchiveWorker::open(&directory).unwrap());
        restored.evidence_vault = EvidenceVault::new(directory.join("evidence"));
        restored.traffic_latch.mode = LatchMode::Automatic;
        restored.latch_helper_path = Some("/must-not-run".into());
        restored.filter.input = "stale filter".into();
        restored
            .apply_project_state(serde_json::from_slice(&json).unwrap())
            .unwrap();
        assert!(restored.filter.input.is_empty());
        assert!(restored.core.edit().incidents.active().is_none());
        assert_eq!(restored.core.edit().incidents.incidents[0].id, id);
        assert!(restored.core.edit().incidents.incidents[0].reviewed);
        assert_eq!(
            restored.core.edit().incidents.incidents[0].packet_history[0].bytes,
            [1, 2, 3, 4]
        );
        let report = restored
            .query_core(|core| {
                crate::analysis::impact::correlate(
                    &core.incidents.incidents[0],
                    &core.endpoint_evidence,
                )
            })
            .unwrap();
        assert!(!report.compromise_confirmed);
        assert!(
            report
                .evidence
                .iter()
                .any(|entry| entry.subject == "/srv/private.csv"
                    && entry.confidence == ImpactConfidence::Observed)
        );
        assert!(restored.traffic_latch.actions.is_empty());
        assert!(restored.evidence_vault.exports.is_empty());
        assert!(!directory.join("evidence").exists());
        restored.packet_archive.as_mut().unwrap().finish().unwrap();
        let archive =
            crate::storage::packet_archive::PacketArchive::open_readonly(&directory).unwrap();
        assert_eq!(archive.count().unwrap(), 0);
        drop(archive);
        let new_id = restored.core.edit().incidents.open_or_update(
            IncidentSource::UserRule,
            "new",
            "new",
            EvidenceSeverity::Critical,
            &packet(2),
            std::iter::empty(),
        );
        assert!(new_id > id);
        assert!(!restored.live_response_eligible);
        drop(restored);
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn invalid_saved_incidents_do_not_replace_the_open_investigation() {
    let mut app = App::new_for_test();
    app.inject_packet(packet(99));
    let mut state = app
        .snapshot_project("bad", ProjectSaveMode::Portable)
        .unwrap();
    state.incident_state.as_mut().unwrap().last_id = u64::MAX;
    assert!(app.apply_project_state(state).is_err());
    assert_eq!(app.packets[0].no, 99);
}
