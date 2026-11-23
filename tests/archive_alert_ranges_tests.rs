use std::{io::Write, process::Command};

use packrat_tui::analysis::alert_center::AlertCenter;
use serde_json::{Value, json};

#[test]
fn archive_filters_id_ranges_before_limiting_the_results() {
    let dir = tempfile::tempdir().unwrap();
    let active = dir.path().join("alerts.jsonl");
    let previous = dir.path().join("older.jsonl");
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "HIGH", "Saved alert", "fixture");
    let mut alert = center.items.remove(0);
    alert.capture_id = Some("capture-a".into());
    let mut record = |id, session| {
        alert.id = id;
        json!({"schema_version":1,"record_type":"alert","session_id":session,"alert":alert})
    };
    let mut older = std::fs::File::create(&previous).unwrap();
    for id in [1, 2, 4, 6] {
        writeln!(older, "{}", record(id, "session-a")).unwrap();
    }
    let mut log = std::fs::File::create(&active).unwrap();
    writeln!(log, "{}", record(2, "session-a")).unwrap();
    writeln!(log, "{}", record(3, "session-b")).unwrap();
    for id in 9..=530 {
        writeln!(log, "{}", record(id, "session-a")).unwrap();
    }
    let command = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
            .arg("--alerts")
            .arg(&active)
            .arg("--previous-log")
            .arg(&previous)
            .args([
                "--session",
                "session-a",
                "--capture-id",
                "capture-a",
                "--report-integrity",
            ])
            .args(args)
            .output()
            .unwrap()
    };
    let run = |args| {
        let output = command(args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    let ranged = run(&["--alert-range", "2..4", "--alert-range", "4..5"][..]);
    let ids: Vec<_> = ranged["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["alert_id"].as_u64().unwrap())
        .collect();
    assert_eq!(ids, [2, 4]);
    assert_eq!(ranged["integrity"]["stopped_at_limit"], false);
    let limited = run(&["--alert-range", "2..4", "--limit", "1"]);
    assert_eq!(limited["integrity"]["stopped_at_limit"], true);
    let bounded = run(&["--alert-range", "2..4", "--scan-bytes", "1024"]);
    assert_eq!(bounded["alerts"], json!([]));
    assert_eq!(bounded["integrity"]["stopped_at_scan_budget"], true);
    for args in [
        &["--alert-range", "4..2"][..],
        &["--alert-range", "0..4"],
        &["--alert-range", "2..4", "--alert-id", "2"],
        &["--alert-range", "2..4", "--related-to", "2"],
    ] {
        assert!(!command(args).status.success());
    }
}
