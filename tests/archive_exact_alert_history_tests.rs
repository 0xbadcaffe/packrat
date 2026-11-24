use std::{io::Write, process::Command};

use packrat_tui::analysis::alert_center::{AlertCenter, AlertDisposition, AlertFlow, AlertTransport};
use packrat_tui::storage::packet_archive::PacketArchive;
use serde_json::{Value, json};

#[test]
fn saved_trigger_flow_change_is_visible_without_changing_the_frame_set() {
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("alerts.jsonl");
    let archive = directory.path().join("archive");
    drop(PacketArchive::open(&archive).unwrap());
    let tool = env!("CARGO_BIN_EXE_packrat-archive");
    let mut center = AlertCenter::default();
    center.record(4, "IDS", "HIGH", "Retained finding", "fixture");
    let mut alert = center.items[0].clone();
    alert.capture_id = Some("capture-a".into());
    let snapshot = |flow| {
        let mut alert = alert.clone();
        alert.flow = flow;
        std::fs::write(&log, json!({
            "schema_version":1, "record_type":"alert", "session_id":"session-a", "alert":alert
        }).to_string()).unwrap();
        let history = Command::new(tool).arg("--alerts").arg(&log).output().unwrap();
        let summary = Command::new(tool).arg(&archive).arg("--alert-flow-summary").arg(&log)
            .args(["session-a", "1", "--capture-id", "capture-a"]).output().unwrap();
        assert!(history.status.success() && summary.status.success(), "{history:?} {summary:?}");
        let history: Value = serde_json::from_slice(&history.stdout).unwrap();
        let summary: Value = serde_json::from_slice(&summary.stdout).unwrap();
        assert_eq!(history[0]["recorded_trigger_flow_sha256"], summary["recorded_trigger_flow_sha256"]);
        assert_eq!(history[0]["evidence_frame_set_sha256"], summary["evidence_frame_set_sha256"]);
        (summary["evidence_frame_set_sha256"].clone(), summary["recorded_trigger_flow_sha256"].clone())
    };
    let original = AlertFlow {
        transport: AlertTransport::Tcp,
        source: "192.0.2.10:40000".parse().unwrap(),
        destination: "[2001:db8::5]:443".parse().unwrap(),
    };
    let (frames, tuple) = snapshot(Some(original));
    assert_eq!(tuple.as_str().unwrap().len(), 64);
    for changed in [
        AlertFlow { transport: AlertTransport::Udp, ..original },
        AlertFlow { source: "192.0.2.10:40001".parse().unwrap(), ..original },
        AlertFlow { destination: "[2001:db8::6]:443".parse().unwrap(), ..original },
        AlertFlow { source: original.destination, destination: original.source, ..original },
    ] {
        let (other_frames, other_tuple) = snapshot(Some(changed));
        assert_eq!(frames, other_frames);
        assert_ne!(tuple, other_tuple);
    }
    assert_eq!(snapshot(None), (frames, Value::Null));
}

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
