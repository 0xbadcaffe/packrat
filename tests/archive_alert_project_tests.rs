use std::process::Command;

use packrat_tui::analysis::alert_center::AlertCenter;
use packrat_tui::model::project::SavedInvestigationItem;
use packrat_tui::net::packet::CaptureMetadata;
use packrat_tui::net::parser::parse_ethernet;
use packrat_tui::storage::{packet_archive::PacketArchive, project_store};
#[cfg(feature = "terminal-ui")]
use packrat_tui::tabs::Tab;
use serde_json::{Value, json};

#[test]
#[cfg(feature = "terminal-ui")]
fn invalid_startup_project_fails_before_entering_the_terminal() {
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("bad.json");
    std::fs::write(&path, "not a project").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_packrat"))
        .arg("--project").arg(&path).output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid project file"));
}

#[test]
fn archive_cli_creates_a_scoped_project_from_an_older_log_without_overwriting() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let path = root.join("archive");
    let mut archive = PacketArchive::open(&path).unwrap();
    let packet = |n, byte| {
        let mut packet = parse_ethernet(&[byte], n, n as f64);
        if n == 1 {
            packet.capture = Some(CaptureMetadata {
                timestamp: None, captured_length: 1, wire_length: 60, link_type: 1,
                section_id: 0, interface_id: 0, interface_name: None, comments: Vec::new(),
            });
        }
        packet
    };
    archive.append_scoped("previous", &[packet(1, 1), packet(2, 2), packet(4, 4)]).unwrap();
    archive.append_scoped("current", &[packet(2, 99), packet(3, 99)]).unwrap();
    drop(archive);
    let index = rusqlite::Connection::open(path.join("index.sqlite")).unwrap();
    index.execute("UPDATE capture_frames SET packet_id=4 WHERE capture_id='previous' AND frame_number='4'", []).unwrap();
    drop(index);

    let log = root.join("alerts.jsonl");
    let rotated = root.join("alerts.old.jsonl");
    let mut center = AlertCenter::default();
    center.record(2, "IDS", "HIGH", "Saved alert", "fixture");
    let mut alert = center.items.remove(0);
    alert.packet_refs = vec![1, 2, 3, 4];
    let row = |scope: &str| {
        let mut alert = alert.clone();
        alert.capture_id = Some(scope.into());
        json!({"schema_version":1, "record_type":"alert", "session_id":"s", "alert":alert}).to_string() + "\n"
    };
    std::fs::write(&log, row("current")).unwrap();
    std::fs::write(&rotated, row("previous")).unwrap();
    let output = root.join("alert.packrat.json");
    let run = |scope: Option<&str>| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_packrat-archive"));
        cmd.arg(&path).arg("--alert-project").arg(&log).arg("s")
            .arg(alert.id.to_string()).arg(&output).arg("--previous-log").arg(&rotated);
        if let Some(scope) = scope { cmd.args(["--capture-id", scope]); }
        cmd.output().unwrap()
    };
    assert!(!run(None).status.success());
    assert!(!output.exists());
    let result = run(Some("previous"));
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert_eq!(serde_json::from_slice::<Value>(&result.stdout).unwrap(), json!({
        "retained_frames":2,"truncated_frames":1,"length_unknown_frames":1,
        "missing_frames":1,"unreadable_frames":1,"omitted_at_limit":0,
        "trigger_frame":{"frame_number":2,"status":"length_unknown","included":true}
    }));
    let state = project_store::load(&output).unwrap();
    assert_eq!(state.alert_items[0].packet_refs, [1, 2, 3, 4]);
    assert_eq!(state.alert_items[0].capture_id.as_deref(), Some("previous"));
    assert_eq!(state.pinned_packets.iter().map(|p| (p.no, p.bytes[0])).collect::<Vec<_>>(), [(1, 1), (2, 2)]);
    assert!(state.pinned_packet_scopes.values().all(|id| id == "previous"));
    assert!(state.metadata.description.as_deref().unwrap().contains("1 truncated, 1 length unknown"));
    assert_eq!(state.investigation_items[state.active_investigation.unwrap()], SavedInvestigationItem::Packet(2));
    assert_eq!(state.active_tab, 1);
    #[cfg(feature = "terminal-ui")]
    assert_eq!(Tab::from_index(state.active_tab), Tab::Investigate);
    let original = std::fs::read(&output).unwrap();
    assert!(!run(Some("current")).status.success());
    assert_eq!(std::fs::read(&output).unwrap(), original);
}

#[test]
fn archive_project_opens_on_the_alert_when_its_trigger_is_missing() {
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("archive");
    let log = scratch.path().join("alerts.jsonl");
    let output = scratch.path().join("case.json");
    let packet = parse_ethernet(&[0; 14], 1, 1.0);
    let mut archive = PacketArchive::open(&path).unwrap();
    archive.append_scoped("scope-a", &[packet.clone()]).unwrap();
    archive.append_scoped("scope-b", &[parse_ethernet(&[0; 14], 2, 2.0)]).unwrap();
    drop(archive);
    let mut center = AlertCenter::default();
    center.record(2, "IDS", "HIGH", "Saved alert", "fixture");
    let mut alert = center.items.remove(0);
    alert.capture_id = Some("scope-a".into());
    alert.packet_refs = vec![1, 2];
    std::fs::write(&log, json!({
        "schema_version":1,"record_type":"alert","session_id":"s","alert":alert
    }).to_string()).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&path).arg("--alert-project").arg(&log).args(["s", "1"]).arg(&output)
        .args(["--capture-id", "scope-a"]).output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["trigger_frame"], json!({"frame_number":2,"status":"missing","included":false}));
    let state = project_store::load(&output).unwrap();
    assert_eq!(state.investigation_items[state.active_investigation.unwrap()],
        SavedInvestigationItem::AlertRef { id: 1, capture_id: Some("scope-a".into()) });
    assert_eq!(state.pinned_packets.iter().map(|packet| packet.no).collect::<Vec<_>>(), [1]);
    assert!(state.metadata.description.as_deref().unwrap().contains("Trigger #2 not included"));
}
