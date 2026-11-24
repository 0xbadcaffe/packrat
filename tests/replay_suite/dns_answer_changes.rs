use super::{dns_replay, run_suite, run_suite_with_baseline};
use serde_json::{Value, json};
use std::process::Command;

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn dns_replay_distinguishes_equivalent_replies_from_changed_answers_and_wire_data() {
    use dns_replay::Scenario;

    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    dns_replay::write_fixture(&root.join("equivalent.pcapng"), Scenario::Equivalent);
    dns_replay::write_fixture(&root.join("answer.pcapng"), Scenario::ChangedAnswer);
    dns_replay::write_fixture(&root.join("wire.pcapng"), Scenario::ChangedWire);
    dns_replay::write_fixture(&root.join("soa-equivalent.pcapng"), Scenario::EquivalentSoa);
    dns_replay::write_fixture(&root.join("soa-changed.pcapng"), Scenario::ChangedSoa);
    dns_replay::write_fixture(
        &root.join("https-equivalent.pcapng"),
        Scenario::EquivalentHttps,
    );
    dns_replay::write_fixture(&root.join("https-changed.pcapng"), Scenario::ChangedHttps);
    dns_replay::write_fixture(&root.join("ech-changed.pcapng"), Scenario::ChangedEch);
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
             "opening_frames": {"dns.changed_wire_reply": [4]}},
            {"name": "same SOA, different compression", "capture": "soa-equivalent.pcapng",
             "expect_snapshots": 0,
             "expect_counts": {"dns.changed_answers": 0, "dns.changed_wire_reply": 0}},
            {"name": "SOA serial changed", "capture": "soa-changed.pcapng",
             "expect_snapshots": 1,
             "expect_counts": {"dns.changed_answers": 1, "dns.changed_wire_reply": 0},
             "opening_frames": {"dns.changed_answers": [4]}},
            {"name": "same HTTPS answer, reordered hints", "capture": "https-equivalent.pcapng",
             "expect_snapshots": 0,
             "expect_counts": {"dns.changed_answers": 0, "dns.changed_wire_reply": 0}},
            {"name": "HTTPS service port changed", "capture": "https-changed.pcapng",
             "expect_snapshots": 1,
             "expect_counts": {"dns.changed_answers": 1, "dns.changed_wire_reply": 0},
             "opening_frames": {"dns.changed_answers": [4]}},
            {"name": "HTTPS ECH config changed", "capture": "ech-changed.pcapng",
             "expect_snapshots": 1,
             "expect_counts": {"dns.changed_answers": 1, "dns.changed_wire_reply": 0},
             "opening_frames": {"dns.changed_answers": [4]}}
        ]
    });
    std::fs::write(&manifest, labels.to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 8);
    assert_eq!(report["cases"][0]["summary"]["alerts_opened"], 0);
    assert_eq!(report["cases"][1]["summary"]["packets"], 5);
    assert_eq!(
        report["cases"][1]["snapshot_check"],
        json!({"expected":1,"observed":1})
    );
    assert_eq!(
        report["cases"][2]["snapshot_check"],
        json!({"expected":1,"observed":1})
    );
    let comparison =
        run_suite_with_baseline(&manifest, Some(env!("CARGO_BIN_EXE_packrat-analyze")));
    assert!(
        comparison.status.success(),
        "{}",
        String::from_utf8_lossy(&comparison.stdout)
    );
    let report: Value = serde_json::from_slice(&comparison.stdout).unwrap();
    assert_eq!(report["comparable"], 8);
    assert_eq!(
        report["cases"][1]["delta"],
        json!({
            "alerts_opened": 0, "alert_snapshots": 0, "unregistered_alerts": 0, "rule_openings": {},
            "missed_opening_frames": 0,
            "unexpected_openings": 0, "count_deficit": 0, "count_surplus": 0
        })
    );
    for (capture, rule, severity, confidence) in [
        (
            "answer.pcapng",
            "dns.changed_answers",
            "MEDIUM",
            "correlated",
        ),
        (
            "https-changed.pcapng",
            "dns.changed_answers",
            "MEDIUM",
            "correlated",
        ),
        ("wire.pcapng", "dns.changed_wire_reply", "LOW", "heuristic"),
        (
            "ech-changed.pcapng",
            "dns.changed_answers",
            "MEDIUM",
            "correlated",
        ),
        (
            "soa-changed.pcapng",
            "dns.changed_answers",
            "MEDIUM",
            "correlated",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
            .arg("--alerts-only")
            .arg(root.join(capture))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let alerts: Vec<Value> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|row| serde_json::from_str::<Value>(row).unwrap())
            .filter(|row| row["type"] == "alert")
            .collect();
        assert_eq!(alerts.len(), 1);
        let alert = &alerts[0]["alert"];
        assert_eq!(alert["provenance"]["rule_id"], rule);
        assert_eq!(alert["provenance"]["revision"], 13);
        assert_eq!(alert["provenance"]["confidence"], confidence);
        assert_eq!(alert["severity"], severity);
        assert_eq!(alert["packet_refs"], json!([1, 2, 4]));
    }
}
