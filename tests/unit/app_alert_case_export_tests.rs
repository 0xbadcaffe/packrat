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
    assert_eq!(report.frames.get(&2), Some(&ArchivedFrameOutcome::Missing));
    let mut review = App::new_for_test();
    review.apply_project_state(project).unwrap();
    review.worklist.active = Some(0);
    let details = review.active_investigation_context().unwrap().details;
    assert!(details.iter().any(|(label, value)| label == "Missing at export" && value == "#2"));
    let mut saved = review.snapshot_project("reviewed", ProjectSaveMode::Lightweight).unwrap();
    assert_eq!(saved.alert_archive_report.as_ref(), Some(&report));
    saved.alert_archive_report.as_mut().unwrap().frames.insert(2, ArchivedFrameOutcome::OmittedAtLimit);
    review.apply_project_state(saved).unwrap();
    assert!(review.active_investigation_context().unwrap().details.iter().any(|(label, value)|
        label == "Omitted at export (limit)" && value == "#2"));
    review.core.edit().alert_center.items[0].packet_refs.push(3);
    assert!(!review.active_investigation_context().unwrap().details.iter().any(|(label, _)| label.contains("at export")));

    let original = std::fs::read(&output).unwrap();
    app.start_alert_archive_case(output.clone()).unwrap();
    finish_export(&mut app);
    assert!(app.status_msg.as_deref().unwrap().contains("already exists"));
    assert_eq!(std::fs::read(output).unwrap(), original);
}

#[test]
fn selected_alert_archive_export_refuses_unscoped_and_missing_archive() {
    let scratch = tempfile::tempdir().unwrap();
    let output = scratch.path().join("no-case.json");
    let mut app = App::new_for_test();
    app.core.edit().alert_center.record(1, "IDS", "HIGH", "Unscoped finding", "fixture");
    assert!(app.start_alert_archive_case(output.clone()).unwrap_err().contains("no capture ID"));
    app.core.edit().alert_center.items[0].capture_id = Some("old-capture".into());
    assert!(app.start_alert_archive_case(output.clone()).unwrap_err().contains("no packet archive"));
    assert!(!output.exists());
    assert!(app.alert_case_export.is_none());
}
