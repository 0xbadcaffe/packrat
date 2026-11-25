use std::process::Command;

use packrat_tui::analysis::alert_center::AlertCenter;
use packrat_tui::storage::packet_archive::PacketArchive;
use serde_json::{Value, json};

#[test]
fn evidence_lookup_shares_its_budget_across_logs_and_distinguishes_misses() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("archive");
    let active = root.path().join("alerts.jsonl");
    let previous = root.path().join("alerts.jsonl.1");
    let output = root.path().join("evidence");
    drop(PacketArchive::open(&archive).unwrap());

    let mut center = AlertCenter::default();
    center.record(1, "IDS", "HIGH", "Saved finding", "test");
    let row = |capture: &str| {
        let mut alert = center.items[0].clone();
        alert.capture_id = Some(capture.into());
        format!("{}\n", json!({"schema_version":1,"record_type":"alert","session_id":"session-a","alert":alert}))
    };
    let newer = row("capture-b");
    let older = row("capture-a");
    std::fs::write(&active, &newer).unwrap();
    std::fs::write(&previous, &older).unwrap();

    let command = |action, id| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_packrat-archive"));
        command.arg(&archive).arg(action).arg(&active).args(["session-a", id]);
        if action == "--alert-evidence" { command.arg(&output); }
        command.arg("--previous-log").arg(&previous);
        command
    };
    let budget = newer.len().to_string();
    let total = (newer.len() + older.len()).to_string();
    for action in ["--alert-status", "--alert-flow-summary", "--alert-evidence"] {
        let result = command(action, "1").args(["--capture-id", "capture-a", "--scan-bytes", &budget])
            .output().unwrap();
        assert!(!result.status.success() && result.stdout.is_empty());
        assert!(String::from_utf8_lossy(&result.stderr).contains("reached the scan byte limit"));
    }
    assert!(!output.exists());

    let result = command("--alert-status", "1").args(["--capture-id", "capture-a", "--scan-bytes", &total])
        .output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["capture_id"], "capture-a");
    assert_eq!(report["frames"], json!([{"frame_number":1,"status":"missing"}]));

    let missing = command("--alert-status", "2").args(["--capture-id", "capture-a", "--scan-bytes", &total])
        .output().unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("No matching alert"));
    let unscoped = command("--alert-status", "1").args(["--scan-bytes", &budget]).output().unwrap();
    assert!(!unscoped.status.success());
    assert!(String::from_utf8_lossy(&unscoped.stderr).contains("requires --capture-id"));
    assert!(!command("--alert-status", "1").args(["--capture-id", "capture-a", "--scan-bytes", "0"])
        .output().unwrap().status.success());
}
