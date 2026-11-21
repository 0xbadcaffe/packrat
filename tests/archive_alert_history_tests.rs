use std::{io::Write, process::Command};

use packrat_tui::analysis::alert_center::{AlertCenter, AlertDisposition};
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
    assert!(report[0].get("packet_refs").is_none());
    assert!(report[0].get("bytes").is_none());
    assert_eq!(report[1]["session_id"], "session-b");
    assert_eq!(report[2]["capture_id"], "capture-b");

    let limited = run(&["--session", "session-a", "--limit", "1"]);
    assert!(limited.status.success());
    assert_eq!(serde_json::from_slice::<Vec<Value>>(&limited.stdout).unwrap(), report[..1]);
    let scoped = run(&["--capture-id", "capture-b"]);
    assert!(scoped.status.success());
    assert_eq!(serde_json::from_slice::<Vec<Value>>(&scoped.stdout).unwrap(), report[2..]);
    assert!(!run(&["--limit", "513"]).status.success());
}
