use super::*;
use crate::model::project::ProjectState;

#[test]
fn alert_investigation_recovers_archived_frames_without_crossing_captures() {
    use crate::net::packet::CaptureMetadata;
    use crate::storage::packet_archive::{ArchiveWorker, PacketArchive};
    use ratatui::{Terminal, backend::TestBackend};

    let directory = tempfile::tempdir().unwrap();
    let archive = directory.path().join("archive");
    let mut app = App::new_for_test();
    app.set_packet_archive(ArchiveWorker::open(&archive).unwrap()).unwrap();
    let capture_a = app.capture_id.clone().unwrap();
    let mut first = packet(90);
    first.info = "first capture".into();
    first.capture = Some(CaptureMetadata {
        timestamp: None,
        captured_length: first.bytes.len() as u32,
        wire_length: 60,
        link_type: 1,
        interface_id: 0,
        section_id: 0,
        interface_name: None,
        comments: Vec::new(),
    });
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
    assert_eq!(app.alert_trigger_status(&old_alerts[0]), "#2: unchecked in archive");
    app.packet_archive.as_mut().unwrap().finish().unwrap();
    assert!(app.investigate_selected_alert());
    assert_eq!(app.worklist.packet_nos(), [1, 2]);
    assert_eq!(app.worklist.retained_packet(1).unwrap().info, "first capture");
    assert_eq!(
        app.alert_evidence_status(&old_alerts[0]),
        "2/2 retained; 1 truncated; 1 capture lengths unknown"
    );
    let status = app.status_msg.as_deref().unwrap();
    assert!(status.contains("2 archived"));
    assert!(status.contains("1 truncated; 1 capture lengths unknown"));
    let mut terminal = Terminal::new(TestBackend::new(100, 28)).unwrap();
    let mut render = |app: &App| {
        terminal.draw(|frame| crate::ui::draw(frame, app)).unwrap();
        terminal.backend().to_string()
    };
    assert!(render(&app).contains("Length: 4 bytes retained; wire length unknown"));
    app.worklist.add_packet(1);
    assert!(render(&app).contains("Truncated: 4 of 60 bytes captured"));

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

fn scoped_case() -> (String, ProjectState) {
    let mut source = App::new_for_test();
    let scope = App::new_capture_id();
    source.capture_id = Some(scope.clone());
    let mut saved = packet(1);
    saved.info = "saved evidence".into();
    source.packets.push_back(saved);
    {
        let mut core = source.core.edit();
        core.alert_center.capture_id = Some(scope.to_string());
        core.alert_center
            .record(1, "IDS", "MEDIUM", "Scoped finding", "observed");
        core.alert_center.items[0].packet_refs.push(2);
    }
    assert!(source.investigate_selected_alert());
    let state = source
        .snapshot_project("scoped", ProjectSaveMode::Lightweight)
        .unwrap();
    (scope.to_string(), state)
}

#[test]
fn archive_alert_project_opens_at_the_trigger_in_investigate() {
    use crate::storage::{alert_evidence::create_alert_project, alert_history::AlertLogs,
        packet_archive::PacketArchive, project_store};

    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let (scope, state) = scoped_case();
    let alert = &state.alert_items[0];
    let mut archive = PacketArchive::open(&root.join("archive")).unwrap();
    archive.append_scoped(&scope, &state.pinned_packets).unwrap();
    let log = root.join("alerts.jsonl");
    let record = serde_json::json!({"schema_version":1,"record_type":"alert","session_id":"s","alert":alert});
    std::fs::write(&log, format!("{record}\n")).unwrap();
    let output = root.join("case.json");
    create_alert_project(&mut archive, AlertLogs::new(&log, &[]).unwrap(), "s", &scope, alert.id, &output).unwrap();

    let (tx, _) = tokio::sync::mpsc::channel(1);
    let mut app = App::new_with_mode(tx, StartupMode::OfflineReview);
    app.open_project(&output).unwrap();
    assert_eq!(project_store::load(&output).unwrap().alert_items.len(), 1);
    assert!(!app.picking_iface && !app.capturing && !app.save_alerts);
    assert!(app.iface_list.is_empty());
    app.switch_interface();
    app.toggle_capture();
    app.toggle_alert_saving();
    assert!(!app.picking_iface && !app.capturing && !app.save_alerts);
    assert!(app.core.edit().alert_jsonl_writer.is_none());
    assert_eq!(app.active_tab, Tab::Investigate);
    assert!(app.worklist.open);
    assert_eq!(app.worklist.active_packet_no(), Some(1));
    assert_eq!(app.active_investigation_packet().unwrap().info, "saved evidence");
    assert!(app.investigate_selected_alert());
    assert!(app.status_msg.as_deref().unwrap().contains("1 unavailable (saved case)"));
}

#[test]
fn restored_alert_opens_only_verified_pins_and_preserves_scope_on_resave() {
    let (scope, state) = scoped_case();
    let other_scope = App::new_capture_id();
    let file = serde_json::to_vec(&state).unwrap();
    let state: ProjectState = serde_json::from_slice(&file).unwrap();
    assert_eq!(state.pinned_packet_scopes.get(&1), Some(&scope));

    let mut restored = App::new_for_test();
    restored.capture_id = Some(other_scope);
    restored.apply_project_state(state).unwrap();
    let alert = restored.core.edit().alert_center.items[0].clone();
    assert_eq!(
        restored.alert_evidence_status(&alert),
        "1/2 retained in saved case; 1 capture lengths unknown; 1 unavailable"
    );
    restored.inject_packet(packet(2));
    assert_eq!(restored.packets.back().unwrap().no, 3);
    assert!(restored.investigate_selected_alert());
    assert_eq!(restored.worklist.active_packet_no(), Some(1));
    assert_eq!(restored.packet_by_no(1).unwrap().info, "saved evidence");
    assert!(
        restored
            .status_msg
            .as_deref()
            .unwrap()
            .contains("1 unavailable (saved case)")
    );
    let resaved = restored
        .snapshot_project("resaved", ProjectSaveMode::Lightweight)
        .unwrap();
    assert_eq!(resaved.pinned_packet_scopes.get(&1), Some(&scope));
}

#[test]
fn legacy_and_mismatched_pins_are_not_relabelled_or_linked() {
    for legacy in [true, false] {
        let (_, mut state) = scoped_case();
        if legacy {
            state.metadata.schema_version = 5;
            state.pinned_packet_scopes.clear();
        } else {
            state
                .pinned_packet_scopes
                .insert(1, App::new_capture_id().to_string());
        }
        let original_scopes = state.pinned_packet_scopes.clone();

        let mut restored = App::new_for_test();
        restored.capture_id = Some(App::new_capture_id());
        restored.apply_project_state(state).unwrap();
        assert!(restored.investigate_selected_alert());
        assert_eq!(restored.worklist.active_packet_no(), None);
        assert!(restored.worklist.retained_packet(1).is_some());
        let resaved = restored
            .snapshot_project("resaved", ProjectSaveMode::Lightweight)
            .unwrap();
        assert_eq!(resaved.pinned_packet_scopes, original_scopes);
    }
}

#[test]
fn invalid_pin_scope_metadata_is_rejected() {
    let (scope, mut state) = scoped_case();
    state.pinned_packet_scopes.insert(2, scope);
    let mut restored = App::new_for_test();
    assert!(restored.apply_project_state(state).is_err());
}

#[test]
fn alert_investigation_skips_invalid_capture_lengths_without_hiding_other_frames() {
    let mut app = App::new_for_test();
    let mut invalid = packet(10);
    invalid.capture = Some(crate::net::packet::CaptureMetadata {
        timestamp: None,
        captured_length: 3,
        wire_length: 60,
        link_type: 1,
        interface_id: 0,
        section_id: 0,
        interface_name: None,
        comments: Vec::new(),
    });
    app.packets.extend([invalid, packet(20)]);
    let alert = {
        let mut core = app.core.edit();
        core.alert_center.record(10, "IDS", "HIGH", "Mixed lengths", "test");
        core.alert_center.items[0].packet_refs = vec![10, 20];
        core.alert_center.items[0].clone()
    };
    assert_eq!(
        app.alert_evidence_status(&alert),
        "1/2 retained; 1 capture lengths unknown; 1 invalid capture lengths; capture ID not recorded"
    );
    assert!(app.investigate_selected_alert());
    assert_eq!(app.worklist.packet_nos(), [20]);
    assert!(matches!(app.active_investigation_item(), Some(InvestigationItem::Alert(1))));
    assert!(app.active_investigation_context().unwrap().details.iter().any(|(label, value)|
        label == "Trigger frame" && value == "#10: invalid capture lengths"));
    assert!(app.status_msg.as_deref().unwrap().contains("1 unavailable (1 invalid capture lengths); trigger #10 not opened"));
    app.worklist_next_packet();
    assert_eq!(app.worklist.active_packet_no(), Some(20));
}

#[test]
fn alert_open_repairs_unreadable_pin_from_verified_same_capture_archive_only() {
    use crate::net::packet::CaptureMetadata;
    use crate::storage::packet_archive::ArchiveWorker;

    let scratch = tempfile::tempdir().unwrap();
    let mut app = App::new_for_test();
    let path = scratch.path().join("archive");
    app.set_packet_archive(ArchiveWorker::open(&path).unwrap()).unwrap();
    let scope = app.capture_id.clone().unwrap();
    let complete = |frame| {
        let mut pkt = packet(frame);
        let length = pkt.bytes.len() as u32;
        pkt.capture = Some(CaptureMetadata {
            captured_length: length, wire_length: length, timestamp: None, link_type: 1,
            section_id: 0, interface_id: 0, interface_name: None, comments: Vec::new(),
        });
        pkt
    };
    let archived = complete(10);
    let archive = app.packet_archive.as_mut().unwrap();
    archive.record_scoped(&scope, &archived).unwrap();
    archive.record_scoped(&std::sync::Arc::from("other-capture"), &complete(20)).unwrap();
    archive.finish().unwrap();

    let unreadable = |frame| {
        let mut pkt = complete(frame);
        pkt.bytes.push(99);
        pkt
    };
    app.worklist.pin_packet(&unreadable(10)).unwrap();
    app.packets.push_back(unreadable(20));
    let alert = {
        let mut core = app.core.edit();
        core.alert_center.record(10, "IDS", "HIGH", "Scoped archive fallback", "test");
        core.alert_center.items[0].packet_refs = vec![10, 20];
        core.alert_center.items[0].clone()
    };
    assert_eq!(alert.capture_id.as_deref(), Some(scope.as_ref()));
    assert!(app.investigate_selected_alert());
    assert_eq!(app.worklist.packet_nos(), [10]);
    assert_eq!(app.worklist.retained_packet(10).unwrap().bytes, archived.bytes);
    assert_eq!(app.worklist.retained_bytes, crate::model::project::pinned_packet_cost(&archived));
    assert_eq!(app.worklist.active_packet_no(), Some(10));
    assert!(app.status_msg.as_deref().unwrap().contains("opened 1 matching packets (1 archived); 1 unavailable (1 invalid capture lengths)"));
}
