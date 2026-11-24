use std::{io::Write, process::Command};

use packrat_tui::analysis::alert_center::{AlertCenter, AlertDisposition, AlertFlow, AlertTransport};
use serde_json::{Value, json};

#[test]
fn review_latency_uses_only_usable_timings_in_the_requested_latest_sample() {
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("alerts.jsonl");
    let mut file = std::fs::File::create(&log).unwrap();
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "HIGH", "Saved alert", "fixture");
    let item = center.items.remove(0);
    for (id, scope, saved, reviewed) in [
        (1, Some("capture-a"), Some(1000), Some(9000)),
        (1, Some("capture-a"), Some(1000), Some(1100)),
        (2, Some("capture-a"), Some(1000), Some(1401)),
        (3, Some("capture-a"), None, Some(1600)),
        (4, Some("capture-b"), Some(1500), Some(1400)),
        (5, None, Some(1000), Some(1090)),
        (6, Some("capture-b"), Some(1000), None),
    ] {
        let mut alert = item.clone();
        alert.id = id;
        alert.capture_id = scope.map(str::to_owned);
        alert.first_reviewed_unix_ms = reviewed;
        writeln!(file, "{}", json!({"schema_version":1,"record_type":"alert","session_id":"test-session",
            "first_saved_unix_ms":saved,"alert":alert})).unwrap();
    }
    drop(file);
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
            .arg("--alerts").arg(&log).arg("--report-integrity").args(args).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    assert_eq!(run(&[])["review_latency"], json!({
        "sampled_alerts":6,"measured_alerts":2,"unmeasured_alerts":4,"min_ms":100,"median_ms":250,"max_ms":401,
        "unmeasured_reasons":{"missing_capture_scope":1,"missing_first_save":1,"missing_first_review":1,"review_before_save":1}
    }));
    assert_eq!(run(&["--capture-id", "capture-a"])["review_latency"]["sampled_alerts"], 3);
    let limited = run(&["--limit", "2"]);
    assert_eq!(limited["integrity"]["stopped_at_limit"], true);
    assert_eq!(limited["review_latency"], json!({
        "sampled_alerts":2,"measured_alerts":0,"unmeasured_alerts":2,"min_ms":null,"median_ms":null,"max_ms":null,
        "unmeasured_reasons":{"missing_capture_scope":1,"missing_first_save":0,"missing_first_review":1,"review_before_save":0}
    }));
}

#[test]
fn legacy_rule_hint_does_not_infer_provenance_or_match_titles_from_other_sources() {
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("alerts.jsonl");
    let mut file = std::fs::File::create(&log).unwrap();
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "CRITICAL", "Conflicting DNS responses", "fixture");
    let original = center.items.remove(0);
    for (id, source, scoped, versioned) in [
        (1, "IDS", false, false),
        (2, "OTHER", false, false),
        (3, "IDS", true, false),
        (4, "IDS", false, true),
    ] {
        let mut alert = original.clone();
        alert.id = id;
        alert.source = source.into();
        alert.capture_id = scoped.then(|| "a".repeat(32));
        if !versioned {
            alert.provenance = None;
        }
        writeln!(file, "{}", json!({"schema_version":1,"record_type":"alert",
            "session_id":"legacy","alert":alert})).unwrap();
    }
    drop(file);
    let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg("--alerts").arg(&log).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let rows: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows.len(), 4);
    for alert in rows {
        if alert["alert_id"] == 1 {
            assert_eq!(alert["legacy_rule_hint"], "dns.competing_responders");
            for key in ["capture_id", "rule_id", "revision", "confidence", "verify"] {
                assert!(alert[key].is_null(), "{key}");
            }
        } else {
            assert!(alert.get("legacy_rule_hint").is_none());
        }
    }
}

#[test]
fn saved_alert_history_omits_legacy_credentials_without_rewriting_the_log() {
    use packrat_tui::analysis::alert_provenance::{AlertProvenance, EvidenceConfidence};

    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("alerts.jsonl");
    let mut center = AlertCenter::default();
    center.record(1, "CREDENTIAL", "HIGH", "fixture-only-title", "fixture");
    let mut legacy = center.items[0].clone();
    legacy.detail = "Exposed credential value: fixture-only-value".into();
    legacy.provenance = Some(AlertProvenance {
        rule_id: "fixture-only-rule".into(), revision: 1, confidence: EvidenceConfidence::DirectObservation,
        verification_hint: "fixture-only-hint".into(),
    });
    let mut registered = legacy.clone();
    registered.id = 2;
    registered.title = "HTTP-BasicAuth".into();
    registered.provenance = None;
    let row = |alert| json!({"schema_version":1,"record_type":"alert","session_id":"legacy","alert":alert});
    let original = format!("{}\n{}\n", row(legacy), row(registered));
    std::fs::write(&log, &original).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg("--alerts").arg(&log).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let summary = String::from_utf8(output.stdout).unwrap();
    assert!(summary.contains("value omitted"));
    assert!(!summary.contains("fixture-only-"));
    let rows: Vec<Value> = serde_json::from_str(&summary).unwrap();
    assert_eq!(rows[0]["title"], "HTTP-BasicAuth");
    assert_eq!(rows[1]["title"], "Possible cleartext credential material");
    assert_eq!(rows[1]["severity"], "HIGH");
    assert_eq!(rows[1]["evidence_frame_count"], 1);
    assert_eq!(rows[1]["review_limitations"], json!(["capture_scope_not_recorded","credential_metadata_redacted"]));
    for key in ["rule_id", "revision", "confidence", "verify"] {
        assert!(rows[1][key].is_null(), "{key}");
    }
    assert_eq!(std::fs::read_to_string(log).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn archive_rejects_fifo_alert_logs_without_waiting_for_a_writer() {
    use std::{
        ffi::CString,
        os::unix::{ffi::OsStrExt, fs::symlink},
        process::Stdio,
        thread,
        time::{Duration, Instant},
    };

    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("regular.jsonl");
    std::fs::write(&log, "").unwrap();
    let fifo = directory.path().join("pipe.jsonl");
    let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: fifo_name is a valid, null-terminated path in our temporary directory.
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
    let fifo_alias = directory.path().join("linked-pipe.jsonl");
    symlink(&fifo, &fifo_alias).unwrap();

    for paths in [vec![fifo], vec![log.clone(), "--previous-log".into(), fifo_alias]] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
            .arg("--alerts").args(paths).stderr(Stdio::piped()).spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().ok();
                child.wait().unwrap();
                panic!("Archive CLI blocked on a non-regular log");
            }
            thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("Not a regular alert log"));
    }

    let regular_alias = directory.path().join("linked-regular.jsonl");
    symlink(&log, &regular_alias).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg("--alerts").arg(regular_alias).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(serde_json::from_slice::<Value>(&output.stdout).unwrap(), json!([]));
}

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
    assert_eq!(report[0]["reader_rule_revision"], report[0]["revision"]);
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
        "alerts": [],
        "review_latency": {"sampled_alerts":0,"measured_alerts":0,"unmeasured_alerts":0,"min_ms":null,"median_ms":null,"max_ms":null,
            "unmeasured_reasons":{"missing_capture_scope":0,"missing_first_save":0,"missing_first_review":0,"review_before_save":0}},
        "integrity": {
            "invalid_records": 1, "oversized_records": 1, "stopped_at_limit": false
        }
    }));
}

#[test]
fn recent_alert_budget_is_shared_and_skips_the_partial_boundary_record() {
    let directory = tempfile::tempdir().unwrap();
    let active = directory.path().join("active.jsonl");
    let previous = directory.path().join("previous.jsonl");
    let mut alerts = AlertCenter::default();
    alerts.record(1, "IDS", "MEDIUM", "Finding", "observed");
    let row = |id| {
        let mut alert = alerts.items[0].clone();
        alert.id = id;
        format!("{}\n", json!({
            "schema_version":1,"record_type":"alert","session_id":"session-a","alert":alert
        }))
    };
    let latest = row(3);
    let middle = row(2);
    let oldest = row(1);
    std::fs::write(&active, &latest).unwrap();
    std::fs::write(&previous, format!("{oldest}{middle}")).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
            .arg("--alerts").arg(&active).arg("--previous-log").arg(&previous)
            .args(args).output().unwrap()
    };
    let ids = |report: &Value| {
        report["alerts"].as_array().unwrap().iter()
            .map(|row| row["alert_id"].as_u64().unwrap()).collect::<Vec<_>>()
    };
    for extra in [0, 10] {
        let budget = (latest.len() + middle.len() + extra).to_string();
        let output = run(&["--scan-bytes", &budget, "--report-integrity"]);
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(ids(&report), [3, 2], "extra={extra}");
        assert_eq!(report["integrity"], json!({
            "invalid_records":0, "oversized_records":0,
            "stopped_at_limit":false, "stopped_at_scan_budget":true,
        }));
    }

    let all_bytes = (latest.len() + middle.len() + oldest.len()).to_string();
    let output = run(&["--scan-bytes", &all_bytes, "--report-integrity"]);
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(ids(&report), [3, 2, 1]);
    assert_eq!(report["integrity"]["stopped_at_scan_budget"], Value::Null);
    assert!(!run(&["--scan-bytes", &all_bytes]).status.success());
    assert!(!run(&["--scan-bytes", "0", "--report-integrity"]).status.success());
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
    assert!(report[0].get("reader_rule_revision").is_none());
    assert_eq!(report[0]["verify"], Value::Null);
    assert_eq!(report[0]["review_limitations"], json!([
        "capture_scope_not_recorded", "rule_provenance_not_recorded", "no_packet_references"
    ]));
}

#[test]
fn history_compares_revisions_without_reclassifying_saved_alerts() {
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("alerts.jsonl");
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "HIGH", "High-entropy outbound transfer", "historical finding");
    let mut alert = center.items[0].clone();
    alert.capture_id = Some("capture-a".into());
    let provenance = alert.provenance.as_mut().unwrap();
    let reader = provenance.revision;
    provenance.revision -= 1;
    let mut unknown = alert.clone();
    unknown.id += 1;
    unknown.provenance.as_mut().unwrap().rule_id = "custom.other".into();
    let rows = [alert, unknown].map(|alert| json!({"schema_version":1,"record_type":"alert","session_id":"lab","alert":alert}).to_string());
    std::fs::write(&log, rows.join("\n") + "\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive")).arg("--alerts").arg(log).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let rows: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    let old = rows.iter().find(|row| row["alert_id"] == 1).unwrap();
    assert_eq!(old["severity"], "HIGH");
    assert_eq!(old["revision"], reader - 1);
    assert_eq!(old["reader_rule_revision"], reader);
    assert_eq!(old["review_limitations"], json!(["rule_revision_differs_from_reader"]));
    let custom = rows.iter().find(|row| row["alert_id"] == 2).unwrap();
    assert!(custom.get("reader_rule_revision").is_none());
    assert_eq!(custom["review_limitations"], json!([]));
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
