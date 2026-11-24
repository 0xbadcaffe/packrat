use super::*;
use crate::model::project::{ArchivedFrameOutcome, SavedInvestigationItem};
use crate::storage::{packet_archive::ArchiveWorker, project_store};

fn finish_export(app: &mut App) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while app.alert_case_export.is_some() {
        app.poll_alert_case_export();
        assert!(std::time::Instant::now() < deadline, "archive case export did not finish");
        std::thread::yield_now();
    }
}

#[test]
fn selected_alert_archive_export_keeps_the_exact_historical_capture_separate() {
    let scratch = tempfile::tempdir().unwrap();
    let archive_path = scratch.path().join("archive");
    let output = scratch.path().join("case.json");
    let mut app = App::new_for_test();
    app.set_packet_archive(ArchiveWorker::open(&archive_path).unwrap()).unwrap();
    let live_scope = app.capture_id.clone().unwrap();
    let past_scope: std::sync::Arc<str> = "historical-capture".into();
    let mut historical = packet(1);
    historical.info = "historical packet".into();
    historical.capture = Some(crate::net::packet::CaptureMetadata {
        timestamp: None, captured_length: 4, wire_length: 60, link_type: 1,
        section_id: 0, interface_id: 0, interface_name: None, comments: Vec::new(),
    });
    app.packet_archive.as_ref().unwrap().record_scoped(&past_scope, &historical).unwrap();
    let mut live = packet(1);
    live.info = "live packet".into();
    app.inject_packet(live);
    app.packet_archive.as_mut().unwrap().finish().unwrap();
    let (old, current) = {
        let mut core = app.core.edit();
        core.alert_center.record(1, "IDS", "MEDIUM", "Live finding", "fixture");
        let current = core.alert_center.items[0].clone();
        let mut old = current.clone();
        old.capture_id = Some(past_scope.to_string());
        old.title = "Historical finding".into();
        old.packet_refs.push(2);
        core.alert_center.restore(vec![old.clone(), current.clone()], AutomationMode::Off);
        (old, current)
    };
    app.start_alert_archive_case(output.clone()).unwrap();
    assert!(app.start_alert_archive_case(output.clone()).is_err());
    app.core.edit().alert_center.next();
    finish_export(&mut app);

    let project = project_store::load(&output).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&output).unwrap().permissions().mode() & 0o077, 0);
    }
    assert_eq!(project.alert_items, [old]);
    assert_eq!(project.investigation_items, [
        SavedInvestigationItem::AlertRef { id: current.id, capture_id: Some(past_scope.to_string()) },
        SavedInvestigationItem::Packet(1),
    ]);
    assert_eq!(project.active_investigation, Some(1));
    assert_eq!(project.pinned_packets.len(), 1);
    assert_eq!(project.pinned_packets[0].info, historical.info);
    assert_eq!(project.pinned_packet_scopes[&1], past_scope.as_ref());
    assert!(app.status_msg.as_deref().unwrap().contains("1 retained, 1 missing"));
    assert!(app.worklist.items.is_empty());
    assert_eq!(app.capture_id, Some(live_scope));
    assert_eq!(app.packets[0].info, "live packet");

    let report = project.alert_archive_report.clone().unwrap();
    assert_eq!(report.capture_id, past_scope.as_ref());
    assert_eq!(report.session_id, None);
    assert_eq!(report.frames.get(&1), Some(&ArchivedFrameOutcome::Truncated));
    assert_eq!(report.frames.get(&2), Some(&ArchivedFrameOutcome::Missing));
    let mut review = App::new_for_test();
    review.apply_project_state(project).unwrap();
    review.worklist.active = Some(0);
    let details = review.active_investigation_context().unwrap().details;
    assert!(details.iter().any(|(label, value)| label == "Missing at export" && value == "#2"));
    assert!(details.iter().any(|(label, value)| label == "Truncated at export" && value == "#1"));
    assert!(!details.iter().any(|(label, _)| label == "Not pinned now"));
    let mut saved = review.snapshot_project("reviewed", ProjectSaveMode::Lightweight).unwrap();
    assert_eq!(saved.alert_archive_report.as_ref(), Some(&report));
    saved.alert_archive_report.as_mut().unwrap().frames.insert(2, ArchivedFrameOutcome::OmittedAtLimit);
    review.apply_project_state(saved).unwrap();
    assert!(review.active_investigation_context().unwrap().details.iter().any(|(label, value)|
        label == "Omitted at export (limit)" && value == "#2"));
    review.worklist.active = Some(1);
    assert_eq!(review.worklist.remove_active(), Some(InvestigationItem::Packet(1)));
    let after_unpin = review.snapshot_project("reviewed", ProjectSaveMode::Lightweight).unwrap();
    assert!(after_unpin.pinned_packets.is_empty());
    review.apply_project_state(after_unpin).unwrap();
    let details = review.active_investigation_context().unwrap().details;
    assert!(details.iter().any(|(label, value)| label == "Not pinned now" && value == "#1"));
    assert!(details.iter().any(|(label, value)| label == "Truncated at export" && value == "#1"));
    review.core.edit().alert_center.items[0].packet_refs.push(3);
    assert!(!review.active_investigation_context().unwrap().details.iter().any(|(label, _)| label.contains("at export")));

    let original = std::fs::read(&output).unwrap();
    app.start_alert_archive_case(output.clone()).unwrap();
    finish_export(&mut app);
    assert!(app.status_msg.as_deref().unwrap().contains("already exists"));
    assert_eq!(std::fs::read(output).unwrap(), original);
}

#[test]
fn selected_alert_case_export_refuses_unscoped_and_wrong_capture_evidence() {
    let scratch = tempfile::tempdir().unwrap();
    let output = scratch.path().join("no-case.json");
    let mut app = App::new_for_test();
    let scope = App::new_capture_id();
    app.clear_packets_for_scope(Some(scope)).unwrap();
    app.inject_packet(packet(1));
    app.core.edit().alert_center.record(1, "IDS", "HIGH", "Unscoped finding", "fixture");
    app.core.edit().alert_center.items[0].capture_id = None;
    assert!(app.start_alert_archive_case(output.clone()).unwrap_err().contains("no capture ID"));
    app.core.edit().alert_center.items[0].capture_id = Some("old-capture".into());
    assert!(app.start_alert_archive_case(output.clone()).unwrap_err().contains("no packet archive"));
    assert!(!output.exists());
    assert!(app.alert_case_export.is_none());
}

#[test]
fn case_export_uses_only_scoped_local_frames_when_no_archive_is_attached() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("local-case.json");
    let mut app = App::new_for_test();
    let scope = App::new_capture_id();
    app.clear_packets_for_scope(Some(scope.clone())).unwrap();
    app.inject_packet(packet(1));
    {
        let mut core = app.core.edit();
        core.alert_center.record(1, "IDS", "HIGH", "Live finding", "fixture");
        core.alert_center.items[0].packet_refs.push(2);
    }
    assert!(app.packet_archive.is_none());
    app.start_alert_archive_case(output.clone()).unwrap();
    finish_export(&mut app);
    let project = project_store::load(&output).unwrap();
    let report = project.alert_archive_report.unwrap();
    assert_eq!(report.capture_id, scope.as_ref());
    assert_eq!(report.session_id.as_deref(), Some(app.alert_session_id.as_ref()));
    assert_eq!(report.local_fallback_frames.into_iter().collect::<Vec<_>>(), [1]);
    assert_eq!(report.frames[&2], ArchivedFrameOutcome::Missing);
    assert_eq!(project.pinned_packets.len(), 1);
    assert_eq!(project.pinned_packets[0].bytes, app.packets[0].bytes);
    assert!(project.metadata.description.unwrap().contains("No archive checked"));
    assert!(app.status_msg.as_deref().unwrap().contains("1 retained, 1 missing"));
}

#[test]
fn selected_alert_archive_export_fills_missing_frames_from_matching_local_evidence() {
    let scratch = tempfile::tempdir().unwrap();
    let output = scratch.path().join("mixed-case.json");
    let mut app = App::new_for_test();
    app.set_packet_archive(ArchiveWorker::open(&scratch.path().join("archive")).unwrap()).unwrap();
    let scope = app.capture_id.clone().unwrap();
    let mut archived = packet(1);
    archived.info = "on disk".into();
    app.packet_archive.as_ref().unwrap().record_scoped(&scope, &archived).unwrap();
    app.packet_archive.as_mut().unwrap().finish().unwrap();

    let mut alternate = packet(1);
    alternate.bytes[0] ^= 1;
    let mut local = packet(2);
    local.info = "only in local buffer".into();
    app.packets.extend([alternate, local.clone(), packet(3)]);
    {
        let mut core = app.core.edit();
        core.alert_center.record(2, "IDS", "HIGH", "Mixed evidence", "fixture");
        core.alert_center.items[0].packet_refs.extend([1, 4]);
    }
    app.start_alert_archive_case(output.clone()).unwrap();
    app.packets.clear(); // The export snapshots local evidence before starting its worker.
    finish_export(&mut app);

    let project = project_store::load(&output).unwrap();
    let report = project.alert_archive_report.as_ref().unwrap();
    assert_eq!(report.session_id.as_deref(), Some(app.alert_session_id.as_ref()));
    assert_eq!(report.local_fallback_frames.iter().copied().collect::<Vec<_>>(), [2]);
    assert_eq!(report.frames.get(&4), Some(&ArchivedFrameOutcome::Missing));
    assert!(!report.frames.contains_key(&3));
    assert_eq!(project.pinned_packets[0].bytes, archived.bytes);
    assert_eq!(project.pinned_packets[1].bytes, local.bytes);
    assert_eq!(project.active_investigation, Some(2));
    assert!(app.status_msg.as_deref().unwrap().contains("1 from local evidence"));
    let mut review = App::new_for_test();
    review.apply_project_state(project).unwrap();
    review.worklist.active = Some(0);
    assert!(review.active_investigation_context().unwrap().details.iter()
        .any(|(label, value)| label == "Local evidence at export" && value == "#2"));
}

#[test]
fn reexport_preserves_the_recorded_historical_session_without_relabeling_it() {
    let scratch = tempfile::tempdir().unwrap();
    let archive = scratch.path().join("archive");
    let mut app = App::new_for_test();
    app.set_packet_archive(ArchiveWorker::open(&archive).unwrap()).unwrap();
    let scope = app.capture_id.clone().unwrap();
    app.packet_archive.as_ref().unwrap().record_scoped(&scope, &packet(1)).unwrap();
    app.packet_archive.as_mut().unwrap().finish().unwrap();
    app.core.edit().alert_center.record(1, "IDS", "HIGH", "Saved finding", "fixture");

    let original = scratch.path().join("original.json");
    app.start_alert_archive_case(original.clone()).unwrap();
    finish_export(&mut app);
    let project = project_store::load(&original).unwrap();
    let expected_session = project.alert_archive_report.as_ref().unwrap().session_id.clone().unwrap();

    let mut review = App::new_for_test();
    assert_ne!(review.alert_session_id.as_ref(), expected_session);
    review.apply_project_state(project).unwrap();
    review.worklist.active = Some(0);
    let context = review.active_investigation_context().unwrap();
    assert!(context.details.iter().any(|(label, value)| label == "Alert session" && value == &expected_session));
    let reexport = scratch.path().join("reexport.json");
    review.start_alert_archive_case(reexport.clone()).unwrap();
    finish_export(&mut review);
    let saved = project_store::load(&reexport).unwrap();
    assert_eq!(saved.alert_archive_report.unwrap().session_id.as_deref(), Some(expected_session.as_str()));
}
