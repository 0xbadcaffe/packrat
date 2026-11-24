use packrat_tui::analysis::alert_center::AlertCenter;
use packrat_tui::model::project::{AlertArchiveReport, ArchivedFrameOutcome, ProjectSaveMode, ProjectState};
use packrat_tui::net::{packet::CaptureMetadata, parser::parse_ethernet};
use packrat_tui::storage::project_store;
use serde_json::{Value, json};
use std::process::Command;

#[test]
fn project_status_keeps_recorded_provenance_separate_from_current_pins() {
    let scratch = tempfile::tempdir().unwrap();
    let saved = scratch.path().join("case.json");
    let log = scratch.path().join("alerts.jsonl");
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "MEDIUM", "Fixture", "Private detail");
    let mut alert = center.items.remove(0);
    alert.capture_id = Some("capture-a".into());
    alert.packet_refs = vec![1, 2, 3];
    let save_log = |alert: &_| {
        std::fs::write(
            &log,
            json!({"schema_version":1,"record_type":"alert","session_id":"s","alert":alert})
                .to_string(),
        )
        .unwrap();
    };
    save_log(&alert);

    let mut project = ProjectState::new("case", ProjectSaveMode::Lightweight);
    project.pinned_packets.push(parse_ethernet(&[0; 14], 1, 0.0));
    project.pinned_packet_scopes.insert(1, "capture-a".into());
    project.alert_archive_report = Some(AlertArchiveReport {
        alert_id: 1,
        capture_id: "capture-a".into(),
        session_id: None,
        frames: [
            (1, ArchivedFrameOutcome::LengthUnknown),
            (2, ArchivedFrameOutcome::Complete),
            (3, ArchivedFrameOutcome::OmittedAtLimit),
        ].into_iter().collect(),
        retained_sha256: None,
        local_fallback_frames: [2].into_iter().collect(),
    });
    project_store::create(&project, &saved).unwrap();
    let command = || {
        Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
            .arg("--project-alert-status").arg(&saved).arg(&log)
            .args(["s", "capture-a", "1"]).output().unwrap()
    };
    let run = || {
        let output = command();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains("Private") && !text.contains("\"bytes\""));
        serde_json::from_str::<Value>(&text).unwrap()
    };
    assert_eq!(run()["frames"], json!([
        {"frame_number":1,"status":"length_unknown",
         "project_export":{"recorded_outcome":"length_unknown","recorded_source":"archive"}},
        {"frame_number":2,"status":"missing",
         "project_export":{"recorded_outcome":"complete","recorded_source":"local_fallback"}},
        {"frame_number":3,"status":"missing","project_export":{"recorded_outcome":"omitted_at_limit"}}
    ]));

    alert.packet_refs.push(4);
    save_log(&alert);
    assert!(run()["frames"].as_array().unwrap().iter().all(|frame| frame.get("project_export").is_none()));

    alert.packet_refs.pop();
    save_log(&alert);
    project.alert_archive_report.as_mut().unwrap().session_id = Some("other-session".into());
    project_store::save(&project, &saved).unwrap();
    let rejected = command();
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("different alert session"));
}

#[test]
fn project_bundle_export_refuses_to_relabel_a_recorded_alert_session() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("case.json");
    let log = root.path().join("alerts.jsonl");
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "HIGH", "Saved finding", "fixture");
    let mut alert = center.items.remove(0);
    alert.capture_id = Some("scope-a".into());
    let logs = ["original", "other"].map(|session_id| {
        json!({"schema_version":1,"record_type":"alert","session_id":session_id,"alert":alert})
    });
    std::fs::write(&log, format!("{}\n{}\n", logs[0], logs[1])).unwrap();
    let mut project = ProjectState::new("fixture", ProjectSaveMode::Lightweight);
    let mut packet = parse_ethernet(&[0; 14], 1, 1.0);
    packet.capture = Some(CaptureMetadata {
        timestamp: None, captured_length: 14, wire_length: 14, link_type: 1,
        section_id: 0, interface_id: 0, interface_name: None, comments: Vec::new(),
    });
    project.pinned_packet_scopes.insert(1, "scope-a".into());
    project.pinned_packets.push(packet);
    project.alert_archive_report = Some(AlertArchiveReport {
        alert_id: 1, capture_id: "scope-a".into(), session_id: Some("original".into()),
        frames: [(1, ArchivedFrameOutcome::Complete)].into_iter().collect(),
        retained_sha256: None, local_fallback_frames: Default::default(),
    });
    project_store::create(&project, &file).unwrap();
    let run = |session, output: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
            .arg("--project-alert-evidence").arg(&file).arg(&log)
            .args([session, "scope-a", "1"]).arg(output).output().unwrap()
    };
    let wrong = root.path().join("wrong");
    let rejected = run("other", &wrong);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("different alert session"));
    assert!(!wrong.exists());

    let actual = run("original", &root.path().join("same"));
    assert!(actual.status.success(), "{}", String::from_utf8_lossy(&actual.stderr));
    let actual: Value = serde_json::from_slice(&actual.stdout).unwrap();
    assert_eq!(actual["recovered_frames"], 1);

    project.alert_archive_report.as_mut().unwrap().session_id = None;
    project_store::save(&project, &file).unwrap();
    let legacy = run("original", &root.path().join("legacy"));
    assert!(legacy.status.success(), "{}", String::from_utf8_lossy(&legacy.stderr));
    let legacy: Value = serde_json::from_slice(&legacy.stdout).unwrap();
    assert_eq!(legacy["recovered_frames"], 1);
}
