use std::{io::Write, process::Command};

use packrat_tui::analysis::alert_center::{AlertCenter, AlertDisposition};
use serde_json::{Value, json};

#[test]
fn exact_alert_lookup_reaches_rotated_history_and_rejects_scope_collisions() {
    let directory = tempfile::tempdir().unwrap();
    let previous = directory.path().join("alerts.jsonl.1");
    let active = directory.path().join("alerts.jsonl");
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "MEDIUM", "Retained finding", "previous snapshot");
    let mut alert = center.items[0].clone();
    alert.capture_id = Some("capture-a".into());
    let row = |session, alert| json!({
        "schema_version":1, "record_type":"alert", "session_id":session, "alert":alert
    });
    let mut earlier = std::fs::File::create(&previous).unwrap();
    writeln!(earlier, "{}", row("session-a", alert.clone())).unwrap();
    alert.disposition = AlertDisposition::Benign;
    writeln!(earlier, "{}", row("session-a", alert.clone())).unwrap();

    let mut file = std::fs::File::create(&active).unwrap();
    for id in 2..=65 {
        alert.id = id;
        writeln!(file, "{}", row("session-a", alert.clone())).unwrap();
    }
    alert.id = 1;
    alert.disposition = AlertDisposition::Reviewing;
    writeln!(file, "{}", row("session-b", alert.clone())).unwrap();
    alert.capture_id = Some("capture-b".into());
    writeln!(file, "{}", row("session-a", alert)).unwrap();

    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
            .arg("--alerts").arg(&active)
            .arg("--previous-log").arg(&previous)
            .args(args).output().unwrap()
    };
    let output = run(&["--session", "session-a", "--capture-id", "capture-a",
        "--alert-id", "1", "--report-integrity"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["alerts"].as_array().unwrap().len(), 1);
    assert_eq!(report["alerts"][0]["alert_id"], 1);
    assert_eq!(report["alerts"][0]["disposition"], "Benign");
    assert_eq!(report["integrity"]["stopped_at_limit"], true);

    let missing = run(&["--session", "session-a", "--capture-id", "capture-a", "--alert-id", "99"]);
    assert!(missing.status.success(), "{}", String::from_utf8_lossy(&missing.stderr));
    assert_eq!(serde_json::from_slice::<Value>(&missing.stdout).unwrap(), json!([]));
    assert!(!run(&["--session", "session-a", "--alert-id", "1"]).status.success());
    assert!(!run(&["--session", "session-a", "--capture-id", "capture-a", "--alert-id", "0"]).status.success());
}
