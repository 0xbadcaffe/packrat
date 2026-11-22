#![cfg(target_os = "linux")]

#[path = "support/http.rs"]
mod support;
#[path = "support/dns_replay.rs"]
mod dns_replay;

use packrat_tui::export::pcapng::PcapNgWriter;
use packrat_tui::net::packet::{CaptureMetadata, CaptureTimestamp, TimestampResolution};
use serde_json::{Value, json};
use std::{path::Path, process::{Command, Output}};

fn run_suite(manifest: &Path) -> Output {
    run_suite_with_baseline(manifest, None)
}

fn run_suite_with_baseline(manifest: &Path, baseline: Option<&str>) -> Output {
    let analyzer = Path::new(env!("CARGO_BIN_EXE_packrat-analyze"));
    let existing_path = std::env::var_os("PATH").unwrap_or_default();
    let path = std::env::join_paths(
        std::iter::once(analyzer.parent().unwrap().to_path_buf())
            .chain(std::env::split_paths(&existing_path)),
    )
    .unwrap();
    let suite = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/packrat-replay-suite.sh");
    let mut command = Command::new("bash");
    command.arg(suite)
        .arg(manifest)
        .current_dir("/")
        .env("PATH", path)
        .env_remove("PACKRAT_REPLAY_BASELINE_ANALYZER");
    if let Some(baseline) = baseline {
        command.env("PACKRAT_REPLAY_BASELINE_ANALYZER", baseline);
    }
    command.output().unwrap()
}

fn write_fixture(path: &Path, distinct_responses: bool) {
    let mut capture = PcapNgWriter::create(path).unwrap();
    let response = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
    for frame in 1..=5 {
        let sequence = if distinct_responses {
            frame as u32 * 100
        } else {
            100
        };
        capture
            .write_packet(&support::tcp(frame, sequence, 0x18, response, true))
            .unwrap();
    }
    capture.flush().unwrap();
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn real_analyzer_replay_suite_distinguishes_retransmissions_from_distinct_responses() {
    let scratch = tempfile::tempdir().unwrap();
    write_fixture(&scratch.path().join("repeated replies.pcapng"), false);
    write_fixture(&scratch.path().join("distinct replies.pcapng"), true);
    let manifest = scratch.path().join("suite.json");
    let mut labels = json!({
        "version": 1,
        "strict": true,
        "cases": [
            {
                "name": "benign retransmissions",
                "capture": "repeated replies.pcapng",
                "expect_counts": {"http.unauthorized_burst": 0}
            },
            {
                "name": "distinct authentication replies",
                "capture": "distinct replies.pcapng",
                "expect_counts": {"http.unauthorized_burst": 1},
                "opening_frames": {"http.unauthorized_burst": [5]}
            }
        ]
    });
    let run = || run_suite(&manifest);

    std::fs::write(&manifest, serde_json::to_vec(&labels).unwrap()).unwrap();
    let passing = run();
    assert!(
        passing.status.success(),
        "{}",
        String::from_utf8_lossy(&passing.stderr)
    );
    let report: Value = serde_json::from_slice(&passing.stdout).unwrap();
    assert_eq!(report["passed"], 2);
    assert_eq!(report["cases"][0]["summary"]["alerts_opened"], 0);
    assert_eq!(
        report["cases"][1]["summary"]["rule_counts"]["http.unauthorized_burst"],
        1
    );
    assert_eq!(passing.stdout, run().stdout);
    assert!(!String::from_utf8_lossy(&passing.stdout).contains("401 Unauthorized"));

    labels["cases"][1]["expect_counts"]["http.unauthorized_burst"] = json!(2);
    labels["cases"][1]["opening_frames"]["http.unauthorized_burst"] = json!([4]);
    std::fs::write(&manifest, serde_json::to_vec(&labels).unwrap()).unwrap();
    let mismatched = run();
    assert_eq!(mismatched.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&mismatched.stdout).unwrap();
    assert_eq!(report["failed"], 1);
    assert_eq!(report["inconclusive"], 0);
    let checks = &report["cases"][1]["summary"]["alert_expectations"]["frame_checks"][0];
    assert_eq!(checks["missing_frames"], json!([4]));
    assert_eq!(checks["unexpected_openings"], 1);
    assert_eq!(report["score"], json!({
        "scored_cases": 2, "missed_opening_frames": 1, "unexpected_openings": 1,
        "count_deficit": 0, "count_surplus": 0
    }));

    labels["cases"][1]["expect_counts"] = json!({"scan.horizontal": 0});
    labels["cases"][1]["opening_frames"] = json!({});
    std::fs::write(&manifest, serde_json::to_vec(&labels).unwrap()).unwrap();
    let unlisted = run();
    assert_eq!(unlisted.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&unlisted.stdout).unwrap();
    assert_eq!(
        report["cases"][1]["summary"]["alert_expectations"]["verdict"],
        "passed"
    );
    assert_eq!(
        report["cases"][1]["unlisted_rule_counts"],
        json!({"http.unauthorized_burst": 1})
    );
    assert_eq!(report["cases"][1]["verdict"], "failed");
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn dns_replay_distinguishes_equivalent_replies_from_changed_answers_and_wire_data() {
    use dns_replay::Scenario;

    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    dns_replay::write_fixture(&root.join("equivalent.pcapng"), Scenario::Equivalent);
    dns_replay::write_fixture(&root.join("answer.pcapng"), Scenario::ChangedAnswer);
    dns_replay::write_fixture(&root.join("wire.pcapng"), Scenario::ChangedWire);
    let manifest = root.join("dns.json");
    let labels = json!({
        "version": 1, "strict": true,
        "cases": [
            {"name": "same answer, different TTL and case", "capture": "equivalent.pcapng",
             "expect_snapshots": 0,
             "expect_counts": {"dns.changed_answers": 0, "dns.changed_wire_reply": 0}},
            {"name": "answer content changed", "capture": "answer.pcapng",
             "expect_snapshots": 1,
             "expect_counts": {"dns.changed_answers": 1, "dns.changed_wire_reply": 0},
             "opening_frames": {"dns.changed_answers": [4]}},
            {"name": "unsupported record changed", "capture": "wire.pcapng",
             "expect_snapshots": 1,
             "expect_counts": {"dns.changed_answers": 0, "dns.changed_wire_reply": 1},
             "opening_frames": {"dns.changed_wire_reply": [4]}}
        ]
    });
    std::fs::write(&manifest, labels.to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 3);
    assert_eq!(report["cases"][0]["summary"]["alerts_opened"], 0);
    assert_eq!(report["cases"][1]["summary"]["packets"], 5);
    assert_eq!(report["cases"][1]["snapshot_check"], json!({"expected":1,"observed":1}));
    assert_eq!(report["cases"][2]["snapshot_check"], json!({"expected":1,"observed":1}));
    let comparison = run_suite_with_baseline(&manifest, Some(env!("CARGO_BIN_EXE_packrat-analyze")));
    assert!(comparison.status.success(), "{}", String::from_utf8_lossy(&comparison.stdout));
    let report: Value = serde_json::from_slice(&comparison.stdout).unwrap();
    assert_eq!(report["comparable"], 3);
    assert_eq!(report["cases"][1]["delta"], json!({
        "alerts_opened": 0, "alert_snapshots": 0, "unregistered_alerts": 0, "rule_openings": {},
        "missed_opening_frames": 0,
        "unexpected_openings": 0, "count_deficit": 0, "count_surplus": 0
    }));

    for (capture, rule, severity, confidence) in [
        ("answer.pcapng", "dns.changed_answers", "MEDIUM", "correlated"),
        ("wire.pcapng", "dns.changed_wire_reply", "LOW", "heuristic"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
            .arg("--alerts-only").arg(root.join(capture)).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let alerts: Vec<Value> = String::from_utf8(output.stdout).unwrap().lines()
            .map(|row| serde_json::from_str::<Value>(row).unwrap())
            .filter(|row| row["type"] == "alert").collect();
        assert_eq!(alerts.len(), 1);
        let alert = &alerts[0]["alert"];
        assert_eq!(alert["provenance"]["rule_id"], rule);
        assert_eq!(alert["provenance"]["confidence"], confidence);
        assert_eq!(alert["severity"], severity);
        assert_eq!(alert["packet_refs"], json!([1, 2, 4]));
    }
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn periodic_replay_preserves_wire_lengths_and_capture_interfaces() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let rule = "traffic.periodic_fixed_size";
    let mut cases = Vec::new();
    for (name, vary_size, split_interface, expected) in [
        ("fixed", false, false, 1),
        ("variable wire size", true, false, 0),
        ("split interfaces", false, true, 0),
    ] {
        let file = format!("{name}.pcapng");
        let mut writer = PcapNgWriter::create(&root.join(&file)).unwrap();
        for frame in 1..=7 {
            let mut packet = support::tcp(frame, 100, 0x10, &[], false);
            let captured_length = packet.bytes.len() as u32;
            packet.capture = Some(CaptureMetadata {
                timestamp: Some(CaptureTimestamp {
                    ticks: frame * 10,
                    resolution: TimestampResolution::Decimal(0),
                    offset_seconds: 0,
                }),
                captured_length,
                wire_length: if vary_size && frame % 2 == 0 { 200 } else { 900 },
                link_type: 1,
                interface_id: if split_interface { (frame % 2) as u32 } else { 0 },
                section_id: 0,
                interface_name: None,
                comments: Vec::new(),
            });
            writer.write_packet(&packet).unwrap();
        }
        writer.flush().unwrap();
        let mut case = json!({"name":name, "capture":file, "expect_counts":{(rule):expected}});
        if expected > 0 {
            case["opening_frames"] = json!({(rule):[7]});
        }
        cases.push(case);
    }

    let manifest = root.join("periodic.json");
    let labels = json!({"version":1, "strict":true, "cases":cases});
    std::fs::write(&manifest, labels.to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 3);
    assert_eq!(report["score"]["unexpected_openings"], 0);

    let output = Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
        .arg("--alerts-only").arg(root.join("fixed.pcapng")).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let finding = String::from_utf8(output.stdout).unwrap().lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|event| event["type"] == "alert").unwrap();
    assert_eq!(finding["alert"]["provenance"]["confidence"], "heuristic");
    assert_eq!(finding["alert"]["packet_refs"], json!([1, 2, 3, 4, 5, 6, 7]));
}
