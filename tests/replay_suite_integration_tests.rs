#![cfg(target_os = "linux")]
#[path = "replay_suite/tls.rs"]
mod tls;
#[path = "support/http.rs"]
mod support;
#[path = "support/dns_replay.rs"]
mod dns_replay;
#[path = "support/transfer_replay.rs"]
mod transfer_replay;
#[path = "support/arp.rs"]
mod arp;
#[path = "replay_suite/dtp.rs"]
mod dtp_replay;
#[path = "replay_suite/vlan_tags.rs"]
mod vlan_tags;
#[path = "replay_suite/control_plane.rs"]
mod control_plane;
#[path = "replay_suite/scans.rs"]
mod scans;
#[path = "replay_suite/dhcp.rs"]
mod dhcp;
#[path = "replay_suite/periodic_episodes.rs"]
mod periodic_episodes;
#[path = "replay_suite/auth_retries.rs"]
mod auth_retries;
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
        assert_eq!(alert["provenance"]["revision"], 10);
        assert_eq!(alert["provenance"]["confidence"], confidence);
        assert_eq!(alert["severity"], severity);
        assert_eq!(alert["packet_refs"], json!([1, 2, 4]));
    }
}
#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn dns_replay_keeps_parallel_queries_and_reply_evidence_separate() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let rule = "dns.competing_responders";
    dns_replay::write_parallel_transactions(&root.join("control.pcapng"), false);
    dns_replay::write_parallel_transactions(&root.join("parallel.pcapng"), true);
    let manifest = root.join("parallel.json");
    let labels = json!({"version":1, "strict":true, "cases":[
        {"name":"regular duplicate replies", "capture":"control.pcapng",
         "expect_counts":{(rule):0}, "expect_snapshots":0},
        {"name":"parallel queries with alternate replies", "capture":"parallel.pcapng",
         "expect_counts":{(rule):2}, "opening_frames":{(rule):[5,6]}, "expect_snapshots":3,
         "opening_evidence":[{"rule_id":rule,"opening_frame":5,"frames":[1,3,5]},
                             {"rule_id":rule,"opening_frame":6,"frames":[2,4,6]}]}
    ]});
    std::fs::write(&manifest, labels.to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));

    let output = Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
        .arg("--alerts-only").arg(root.join("parallel.pcapng")).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<_> = String::from_utf8(output.stdout).unwrap().lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|row| row["type"] == "alert")
        .map(|row| row["alert"].clone()).collect();
    assert_eq!(findings.len(), 3);
    assert_ne!(findings[0]["id"], findings[1]["id"]);
    assert_eq!(findings[0]["id"], findings[2]["id"]);
    assert_eq!(findings[1]["packet_refs"], json!([2, 4, 6]));
    assert_eq!(findings[2]["packet_refs"], json!([1, 3, 5, 7]));
    assert_eq!(findings[2]["hit_count"], 2);
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn periodic_replay_preserves_wire_lengths_and_capture_interfaces() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let rule = "traffic.periodic_fixed_size";
    let mut cases = Vec::new();
    for (name, vary_size, split_interface, payload, prefix_frames, sequence_step, expected) in [
        ("fixed", false, false, &[1_u8; 12][..], 0, 12, 1),
        ("variable wire size", true, false, &[1_u8; 12][..], 0, 12, 0),
        ("split interfaces", false, true, &[1_u8; 12][..], 0, 12, 0),
        ("periodic acknowledgements", false, false, &[][..], 0, 0, 0),
        ("fixed after irregular traffic", false, false, &[1_u8; 12][..], 2, 12, 1),
        ("identical TCP retransmissions", false, false, &[1_u8; 12][..], 0, 0, 0),
    ] {
        let file = format!("{name}.pcapng");
        let mut writer = PcapNgWriter::create(&root.join(&file)).unwrap();
        for frame in 1..=7 + prefix_frames {
            let sequence = 100 + (frame as u32 - 1) * sequence_step;
            let mut packet = support::tcp(frame, sequence, 0x10, payload, false);
            let captured_length = packet.bytes.len() as u32;
            packet.capture = Some(CaptureMetadata {
                timestamp: Some(CaptureTimestamp {
                    ticks: if frame <= prefix_frames { frame } else { frame * 10 },
                    resolution: TimestampResolution::Decimal(0),
                    offset_seconds: 0,
                }),
                captured_length,
                wire_length: if payload.is_empty() {
                    captured_length
                } else if frame <= prefix_frames || (vary_size && frame % 2 == 0) {
                    200
                } else {
                    900
                },
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
        if !payload.is_empty() {
            // These fixtures intentionally vary the wire length independently of the captured bytes.
            case["allow_truncated"] = json!(true);
        }
        if expected > 0 {
            case["opening_frames"] = json!({(rule):[7 + prefix_frames]});
            case["opening_evidence"] = json!([{
                "rule_id":rule,"opening_frame":7 + prefix_frames,
                "frames":(1 + prefix_frames..=7 + prefix_frames).collect::<Vec<_>>()
            }]);
        }
        cases.push(case);
    }

    let manifest = root.join("periodic.json");
    let labels = json!({"version":1, "strict":true, "cases":cases});
    std::fs::write(&manifest, labels.to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 6);
    assert_eq!(report["score"]["unexpected_openings"], 0);
    assert_eq!(report["cases"][4]["evidence_checks"][0]["observed_frames"], json!([3, 4, 5, 6, 7, 8, 9]));
    assert_eq!(report["cases"][0]["summary"]["truncated_frames"], 7);
    assert_eq!(report["cases"][3]["summary"]["truncated_frames"], 0);

    let mut mislabeled = labels.clone();
    mislabeled["cases"][4]["opening_evidence"][0]["frames"] = json!([2, 4, 5, 6, 7, 8, 9]);
    std::fs::write(&manifest, mislabeled.to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["failed"], 1);
    assert_eq!(report["score"]["unexpected_openings"], 0);
    assert_eq!(report["cases"][4]["evidence_checks"][0]["passed"], false);

    let mut strict_input = labels;
    strict_input["cases"][0]["allow_truncated"] = json!(false);
    std::fs::write(&manifest, strict_input.to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["inconclusive"], 1);
    assert_eq!(report["cases"][0]["score"], Value::Null);
    let output = Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
        .arg("--alerts-only").arg(root.join("fixed.pcapng")).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let finding = String::from_utf8(output.stdout).unwrap().lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|event| event["type"] == "alert").unwrap();
    assert_eq!(finding["alert"]["provenance"]["confidence"], "heuristic");
    assert_eq!(finding["alert"]["provenance"]["revision"], 12);
    let detail = finding["alert"]["detail"].as_str().unwrap();
    assert!(detail.starts_with("7 TCP packets") && detail.contains("gaps 10.0-10.0s (mean 10.0s), sizes 900-900 bytes on wire, 12-12 captured payload bytes per packet"));
    assert_eq!(finding["alert"]["flow"], json!({
        "transport": "tcp", "source": "10.0.0.1:40000", "destination": "10.0.0.2:80"
    }));
    assert_eq!(finding["alert"]["packet_refs"], json!([1, 2, 3, 4, 5, 6, 7]));
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn industrial_replay_keeps_split_request_evidence_on_its_own_interface() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let write_like = [0, 2, 0, 0, 0, 2, 1, 6];
    let read = [0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1];
    let write_capture = |name: &str, segments: &[(u32, u32, u8, &[u8])]| {
        let mut writer = PcapNgWriter::create(&root.join(name)).unwrap();
        for (index, &(interface_id, sequence, flags, bytes)) in segments.iter().enumerate() {
            let frame = index as u64 + 1;
            let mut packet = support::tcp(frame, sequence, flags, bytes, false);
            packet.bytes[36..38].copy_from_slice(&502_u16.to_be_bytes());
            let length = packet.bytes.len() as u32;
            packet.capture = Some(CaptureMetadata {
                timestamp: Some(CaptureTimestamp { ticks: frame, resolution: TimestampResolution::Decimal(0), offset_seconds: 0 }),
                captured_length: length, wire_length: length, link_type: 1,
                section_id: 0, interface_id, interface_name: None, comments: Vec::new(),
            });
            writer.write_packet(&packet).unwrap();
        }
        writer.flush().unwrap();
    };
    write_capture("benign.pcapng", &[(0, 100, 0x02, &[]), (0, 101, 0x18, &read)]);
    write_capture("scoped.pcapng", &[
        (0, 100, 0x02, &[]), (1, 100, 0x02, &[]),
        (0, 106, 0x18, &write_like[5..]), (1, 106, 0x18, &write_like[5..]),
        (0, 101, 0x18, &write_like[..5]), (1, 101, 0x18, &write_like[..5]),
        (0, 101, 0x18, &write_like[..5]),
    ]);
    let manifest = root.join("industrial.json");
    let rule = "industrial.state_change";
    let labels = json!({"version":1,"strict":true,"cases":[
        {"name":"ordinary read", "capture":"benign.pcapng", "expect_counts":{(rule):0}},
        {"name":"separate streams", "capture":"scoped.pcapng", "expect_counts":{(rule):2},
         "expect_snapshots":2, "opening_frames":{(rule):[5,6]},
         "opening_evidence":[{"rule_id":rule,"opening_frame":5,"frames":[3,5]},
                             {"rule_id":rule,"opening_frame":6,"frames":[4,6]}]}
    ]});
    std::fs::write(&manifest, labels.to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 2);
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn arp_replay_scores_distinct_claim_patterns_and_capture_scopes() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let mut cases = Vec::new();
    let binding = "arp.reply_binding_change";
    let mismatch = "arp.reply_source_mismatch";
    let alternation = "arp.alternating_claims";
    let vlan_shift = "vlan.mac_crossing";
    for (name, sequence, wire_change, expected) in [
        ("ordinary", &[(0, 10, 1), (0, 10, 1)][..], "", json!({})),
        ("vrrp", &[(0, 10, 1)][..], "vrrp", json!({})),
        ("separate-scopes", &[(0, 10, 1), (1, 10, 2), (0, 20, 2), (0, 10, 1)][..], "", json!({})),
        ("same-interface-vlan-shift", &[(0, 10, 1), (0, 20, 1)][..], "", json!({
            "expect_counts":{(vlan_shift):1}, "expect_snapshots":1, "opening_frames":{(vlan_shift):[2]},
            "opening_evidence":[{"rule_id":vlan_shift,"opening_frame":2,"frames":[1,2]}],
        })),
        ("reassigned", &[(0, 10, 1), (0, 10, 2), (0, 10, 2)][..], "", json!({
            "expect_counts":{(binding):1,(alternation):0}, "expect_snapshots":1,
            "opening_frames":{(binding):[2]},
            "opening_evidence":[{"rule_id":binding,"opening_frame":2,"frames":[1,2]}],
        })),
        ("mismatched-sender", &[(0, 10, 1)][..], "mismatch", json!({
            "expect_counts":{(mismatch):1}, "expect_snapshots":1, "opening_frames":{(mismatch):[1]},
            "opening_evidence":[{"rule_id":mismatch,"opening_frame":1,"frames":[1]}],
        })),
        ("alternating", &[(0, 10, 1), (0, 10, 2), (0, 10, 1), (0, 10, 2)][..], "tied-time", json!({
            "expect_counts":{(binding):1,(alternation):1}, "expect_snapshots":5,
            "opening_frames":{(binding):[2],(alternation):[3]},
            "opening_evidence":[{"rule_id":binding,"opening_frame":2,"frames":[1,2]},
                                {"rule_id":alternation,"opening_frame":3,"frames":[1,2,3]}],
        })),
    ] {
        let capture = format!("{name}.pcapng");
        let mut writer = PcapNgWriter::create(&root.join(&capture)).unwrap();
        for (index, &(interface_id, vlan, host)) in sequence.iter().enumerate() {
            let frame = index as u64 + 1;
            let mut packet = arp::reply(frame, frame as f64, vlan, host);
            match wire_change {
                "vrrp" => packet.bytes[26..32].copy_from_slice(&[0, 0, 0x5e, 0, 1, 7]),
                "mismatch" => packet.bytes[11] = 0x25,
                _ => {}
            }
            let (length, ticks) = (packet.bytes.len() as u32, if wire_change == "tied-time" { 1 } else { frame });
            packet.capture = Some(CaptureMetadata {
                timestamp: Some(CaptureTimestamp { ticks, resolution: TimestampResolution::Decimal(0), offset_seconds: 0 }),
                captured_length: length, wire_length: length, link_type: 1,
                section_id: 0, interface_id, interface_name: None, comments: Vec::new(),
            });
            writer.write_packet(&packet).unwrap();
        }
        writer.flush().unwrap();
        let mut case = json!({"name":name,"capture":capture,"expect_snapshots":0,
            "expect_counts":{(binding):0,(mismatch):0,(alternation):0}});
        case.as_object_mut().unwrap().extend(expected.as_object().unwrap().clone());
        cases.push(case);
    }
    let manifest = root.join("arp.json");
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":cases}).to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 7);
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn outbound_transfer_replay_checks_thresholds_scope_and_packet_samples() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let volume = "traffic.asymmetric_outbound";
    let entropy = "traffic.high_entropy_outbound";
    transfer_replay::write_fixture(&root.join("small.pcapng"), 4, true, false);
    transfer_replay::write_fixture(&root.join("split.pcapng"), 17, false, true);
    transfer_replay::write_fixture(&root.join("large.pcapng"), 17, true, false);
    let sparse = (0..20).map(|index| index * 2_400 + (index % 2) * 1_600);
    transfer_replay::write_timed_fixture(&root.join("sparse.pcapng"), sparse, false, false);
    let manifest = root.join("transfers.json");
    let labels = json!({"version":1, "strict":true, "cases":[
        {"name":"small varied transfer", "capture":"small.pcapng",
         "expect_counts":{(volume):0,(entropy):0}, "expect_snapshots":0},
        {"name":"volume split across interfaces", "capture":"split.pcapng",
         "expect_counts":{(volume):0,(entropy):0}, "expect_snapshots":0},
        {"name":"sparse volume over more than an hour", "capture":"sparse.pcapng",
         "expect_counts":{(volume):0,(entropy):0}, "expect_snapshots":0},
        {"name":"large varied transfer", "capture":"large.pcapng",
         "expect_counts":{(volume):1,(entropy):1}, "opening_frames":{(volume):[17],(entropy):[5]},
         "expect_snapshots":2}
    ]});
    std::fs::write(&manifest, labels.to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 4);
    assert_eq!(report["cases"][2]["summary"]["analyzed"], 20);

    let output = Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
        .arg("--alerts-only").arg(root.join("large.pcapng")).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<_> = String::from_utf8(output.stdout).unwrap().lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|row| row["type"] == "alert")
        .map(|row| row["alert"].clone()).collect();
    assert_eq!(findings.len(), 2);
    assert_eq!((findings[0]["severity"].as_str(), &findings[0]["packet_refs"]), (Some("MEDIUM"), &json!([1,2,3,4,5])));
    assert_eq!((findings[1]["severity"].as_str(), &findings[1]["packet_refs"]), (Some("MEDIUM"), &json!([10,11,12,13,14,15,16,17])));
    assert!(findings.iter().all(|alert| alert["provenance"]["confidence"] == "heuristic"));
}
