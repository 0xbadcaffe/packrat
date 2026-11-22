use std::{io::Write, process::Command};

use packrat_tui::analysis::alert_center::{AlertCenter, AlertDisposition, AlertFlow, AlertTransport};
use serde_json::{Value, json};

#[test]
fn alert_history_uses_latest_scoped_snapshots_without_a_packet_archive() {
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("alerts.jsonl");
    let mut file = std::fs::File::create(&log).unwrap();
    let mut center = AlertCenter::default();
    center.record(4, "IDS", "HIGH", "Horizontal host scan", "initial");
    let mut snapshot = center.items[0].clone();
    snapshot.capture_id = Some("capture-a".into());
    let append = |file: &mut std::fs::File, session: &str, alert| {
        writeln!(file, "{}", json!({"schema_version": 1, "record_type":"alert",
            "session_id":session, "alert":alert})).unwrap();
    };
    append(&mut file, "session-a", snapshot.clone());
    let mut other_capture = snapshot.clone();
    other_capture.capture_id = Some("capture-b".into());
    append(&mut file, "session-a", other_capture);
    append(&mut file, "session-b", snapshot.clone());
    writeln!(file, "{}", "x".repeat(1_048_577)).unwrap();
    writeln!(file, "{{incomplete").unwrap();
    snapshot.packet_refs = vec![0, 4, 4, 7];
    snapshot.hit_count = 2;
    snapshot.disposition = AlertDisposition::Benign;
    snapshot.flow = Some(AlertFlow {
        transport: AlertTransport::Tcp,
        source: "[2001:db8::5]:40000".parse().unwrap(),
        destination: "[2001:db8::8]:443".parse().unwrap(),
    });
    append(&mut file, "session-a", snapshot);
    drop(file);

    let run = |args: &[&str]| Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg("--alerts").arg(&log).args(args).output().unwrap();
    let all = run(&[]);
    assert!(all.status.success(), "{}", String::from_utf8_lossy(&all.stderr));
    let report: Vec<Value> = serde_json::from_slice(&all.stdout).unwrap();
    assert_eq!(report.len(), 3);
    assert_eq!(report[0]["session_id"], "session-a");
    assert_eq!(report[0]["capture_id"], "capture-a");
    assert_eq!(report[0]["disposition"], "Benign");
    assert_eq!(report[0]["evidence_frame_count"], 2);
    assert_eq!(report[0]["hit_count"], 2);
    assert_eq!(report[0]["rule_id"], "scan.horizontal");
    assert_eq!(report[0]["review_limitations"], json!([]));
    assert!(report[0].get("packet_refs").is_none());
    assert!(report[0].get("bytes").is_none());
    assert_eq!(report[0]["flow"], json!({
        "transport":"tcp", "source":"[2001:db8::5]:40000", "destination":"[2001:db8::8]:443"
    }));
    assert_eq!(report[1]["session_id"], "session-b");
    assert!(report[1].get("flow").is_none());
    assert_eq!(report[2]["capture_id"], "capture-b");

    let integrity = run(&["--report-integrity", "--session", "session-a"]);
    assert!(integrity.status.success());
    let integrity: Value = serde_json::from_slice(&integrity.stdout).unwrap();
    assert_eq!(integrity["alerts"], json!([report[0], report[2]]));
    assert_eq!(integrity["integrity"], json!({
        "invalid_records": 1, "oversized_records": 1, "stopped_at_limit": false
    }));

    let limited = run(&["--session", "session-a", "--limit", "1"]);
    assert!(limited.status.success());
    assert_eq!(serde_json::from_slice::<Vec<Value>>(&limited.stdout).unwrap(), report[..1]);
    let bounded = run(&["--limit", "1", "--report-integrity"]);
    assert!(bounded.status.success());
    let bounded: Value = serde_json::from_slice(&bounded.stdout).unwrap();
    assert_eq!(bounded["integrity"], json!({
        "invalid_records": 0, "oversized_records": 0, "stopped_at_limit": true
    }));
    let scoped = run(&["--capture-id", "capture-b"]);
    assert!(scoped.status.success());
    assert_eq!(serde_json::from_slice::<Vec<Value>>(&scoped.stdout).unwrap(), report[2..]);
    assert!(!run(&["--limit", "513"]).status.success());
}

#[test]
fn integrity_reports_oversized_first_record_and_invalid_tail_with_no_alerts() {
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("alerts.jsonl");
    std::fs::write(&log, format!("{}\n\n{{partial", "x".repeat(1_048_576))).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg("--alerts").arg(log).arg("--report-integrity").output().unwrap();
    assert!(output.status.success());
    assert_eq!(serde_json::from_slice::<Value>(&output.stdout).unwrap(), json!({
        "alerts": [], "integrity": {
            "invalid_records": 1, "oversized_records": 1, "stopped_at_limit": false
        }
    }));
}

#[test]
fn legacy_history_marks_unverified_scope_without_inheriting_modern_rule_provenance() {
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("alerts.jsonl");
    let mut alerts = AlertCenter::default();
    alerts.record(0, "IDS", "CRITICAL", "Conflicting DNS responses", "legacy finding");
    let mut alert = serde_json::to_value(&alerts.items[0]).unwrap();
    alert.as_object_mut().unwrap().remove("provenance");
    let record = json!({
        "schema_version":1, "record_type":"alert", "session_id":"legacy", "alert":alert
    });
    std::fs::write(&log, format!("{record}\n")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg("--alerts").arg(log).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report[0]["severity"], "CRITICAL");
    assert_eq!(report[0]["rule_id"], Value::Null);
    assert_eq!(report[0]["verify"], Value::Null);
    assert_eq!(report[0]["review_limitations"], json!([
        "capture_scope_not_recorded", "rule_provenance_not_recorded", "no_packet_references"
    ]));
}

#[test]
fn previous_alert_logs_keep_findings_and_use_the_newest_snapshot_across_segments() {
    let directory = tempfile::tempdir().unwrap();
    let earlier = directory.path().join("alerts.jsonl.2");
    let later = directory.path().join("alerts.jsonl.1");
    let active = directory.path().join("alerts.jsonl");
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "MEDIUM", "Retained finding", "first snapshot");
    center.record(2, "IDS", "MEDIUM", "Older finding", "not in the active log");
    let mut first = center.items[0].clone();
    let mut old = center.items[1].clone();
    first.capture_id = Some("capture-a".into());
    old.capture_id = first.capture_id.clone();
    let row = |alert| json!({
        "schema_version":1, "record_type":"alert", "session_id":"session-a", "alert":alert
    });
    std::fs::write(&earlier, format!("{}\n{}\n", row(first.clone()), row(old.clone()))).unwrap();
    old.capture_id = Some("other-capture".into());
    std::fs::write(&later, format!("{}\n", row(old))).unwrap();
    first.disposition = AlertDisposition::Benign;
    std::fs::write(&active, format!("{}\n", row(first))).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg("--alerts").arg(active)
        .arg("--previous-log").arg(earlier)
        .arg("--previous-log").arg(later)
        .args(["--session", "session-a", "--capture-id", "capture-a"])
        .output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report.len(), 2);
    assert_eq!(report[0]["alert_id"], 1);
    assert_eq!(report[0]["disposition"], "Benign");
    assert_eq!(report[1]["alert_id"], 2);
    assert_eq!(report[1]["capture_id"], "capture-a");
}

#[test]
fn recent_history_reads_across_chunks_and_keeps_only_distinct_scoped_alerts() {
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("alerts.jsonl");
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "MEDIUM", "Older matching finding", "first");
    center.record(2, "IDS", "MEDIUM", "Updated finding", "original");
    let row = |session, alert| json!({
        "schema_version":1, "record_type":"alert", "session_id":session, "alert":alert
    });
    let mut older = center.items[0].clone();
    older.capture_id = Some("capture-a".into());
    let mut updated = center.items[1].clone();
    updated.capture_id = older.capture_id.clone();
    let mut file = std::fs::File::create(&log).unwrap();
    writeln!(file, "{}", row("session-a", older)).unwrap();
    writeln!(file, "{}", row("session-a", updated.clone())).unwrap();
    writeln!(file, "{}", "x".repeat(1_048_577)).unwrap();
    updated.detail = "\u{e9}".repeat(40_000);
    updated.hit_count = 42;
    writeln!(file, "{}", row("session-a", updated.clone())).unwrap();
    write!(file, "\n{}", row("another-session", updated)).unwrap();
    drop(file);

    let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg("--alerts").arg(log)
        .args(["--session", "session-a", "--capture-id", "capture-a", "--limit", "2"])
        .output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report.len(), 2);
    assert_eq!(report[0]["alert_id"], 2);
    assert_eq!(report[0]["hit_count"], 42);
    assert_eq!(report[0]["detail"], "\u{e9}".repeat(512));
    assert_eq!(report[1]["alert_id"], 1);
}
