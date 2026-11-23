use std::{io::Write, path::Path, process::Command};

use packrat_tui::analysis::alert_center::{AlertCenter, AlertFlow, AlertTransport};
use serde_json::{Value, json};

const SCOPE: &[&str] = &["--session", "session-a", "--capture-id", "capture-a"];

fn record(id: u64, time: f64, flow: Option<AlertFlow>, session: &str, capture: &str) -> Value {
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "MEDIUM", "Private title", "Private detail");
    let mut alert = center.items.remove(0);
    alert.id = id;
    alert.capture_id = Some(capture.into());
    alert.first_seen = time;
    alert.last_seen = time;
    alert.flow = flow;
    json!({"schema_version": 1, "record_type": "alert", "session_id": session, "alert": alert})
}

fn flow() -> AlertFlow {
    AlertFlow {
        transport: AlertTransport::Tcp,
        source: "192.0.2.10:40001".parse().unwrap(),
        destination: "198.51.100.20:443".parse().unwrap(),
    }
}

fn command(log: &Path, id: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_packrat-archive"));
    command.arg("--alerts").arg(log).args(["--related-to", id]);
    command
}

fn run(log: &Path, id: &str, extra: &[&str]) -> Value {
    let output = command(log, id).args(SCOPE).args(extra).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Private"));
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn relates_only_nearby_exact_tuples_in_the_same_session_and_capture() {
    let forward = flow();
    let reverse = AlertFlow {
        source: forward.destination,
        destination: forward.source,
        ..forward
    };
    let different_port = AlertFlow {
        source: "192.0.2.10:40002".parse().unwrap(),
        ..forward
    };
    let udp = AlertFlow {
        transport: AlertTransport::Udp,
        ..forward
    };
    let directory = tempfile::tempdir().unwrap();
    let previous = directory.path().join("previous.jsonl");
    let active = directory.path().join("alerts.jsonl");
    let mut prior = std::fs::File::create(&previous).unwrap();
    for (id, time, tuple) in [(2, 1000., forward), (3, 1010., forward), (4, 700., reverse)] {
        writeln!(
            prior,
            "{}",
            record(id, time, Some(tuple), "session-a", "capture-a")
        )
        .unwrap();
    }
    let mut current = std::fs::File::create(&active).unwrap();
    for (id, time, tuple, session, capture) in [
        (3, 1010., reverse, "session-a", "capture-a"),
        (5, 1010., forward, "session-a", "capture-a"),
        (6, 699., forward, "session-a", "capture-a"),
        (7, 999., different_port, "session-a", "capture-a"),
        (8, 1000., udp, "session-a", "capture-a"),
        (2, 1000., udp, "session-b", "capture-a"),
        (9, 1000., forward, "session-a", "capture-b"),
    ] {
        writeln!(
            current,
            "{}",
            record(id, time, Some(tuple), session, capture)
        )
        .unwrap();
    }

    let report = run(
        &active,
        "2",
        &["--previous-log", previous.to_str().unwrap()],
    );
    assert_eq!(report["status"], "sampled");
    assert_eq!(report["scan_complete"], true);
    assert_eq!(report["matching_alerts_in_sample"], 3);
    let matches = report["matches"].as_array().unwrap();
    assert_eq!(matches[0]["alert_id"], 3);
    assert_eq!(matches[0]["direction"], "reverse");
    assert_eq!(matches[1]["alert_id"], 5);
    assert_eq!(matches[1]["direction"], "same");
    assert_eq!(matches[2]["seconds_from_anchor_opening"], -300.);
}

#[test]
fn reports_missing_scope_or_tuple_without_implying_no_related_alerts() {
    let mut log = tempfile::NamedTempFile::new().unwrap();
    writeln!(log, "{}", record(1, 100., None, "session-a", "capture-a")).unwrap();
    writeln!(log, "not json").unwrap();
    assert_eq!(run(log.path(), "2", &[])["status"], "anchor_not_in_sample");
    let report = run(log.path(), "1", &[]);
    assert_eq!(report["status"], "anchor_tuple_or_time_unavailable");
    assert_eq!(report["scan_complete"], false);
    assert_eq!(report["integrity"]["invalid_records"], 1);
    assert!(!command(log.path(), "1").output().unwrap().status.success());
    assert!(
        !command(log.path(), "0")
            .args(SCOPE)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        !command(log.path(), "1")
            .args(SCOPE)
            .args(["--alert-id", "1"])
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[test]
fn caps_returned_matches_without_hiding_the_sample_count() {
    let mut log = tempfile::NamedTempFile::new().unwrap();
    for id in 1..=35 {
        writeln!(
            log,
            "{}",
            record(id, id as f64, Some(flow()), "session-a", "capture-a")
        )
        .unwrap();
    }
    let report = run(log.path(), "1", &[]);
    assert_eq!(report["matching_alerts_in_sample"], 34);
    let matches = report["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 32);
    assert_eq!(matches.last().unwrap()["alert_id"], 33);
}
