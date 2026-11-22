#![cfg(target_os = "linux")]

#[path = "support/http.rs"]
mod support;

use packrat_tui::export::pcapng::PcapNgWriter;
use serde_json::{Value, json};
use std::{path::Path, process::Command};

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
    let analyzer = Path::new(env!("CARGO_BIN_EXE_packrat-analyze"));
    let existing_path = std::env::var_os("PATH").unwrap_or_default();
    let path = std::env::join_paths(
        std::iter::once(analyzer.parent().unwrap().to_path_buf())
            .chain(std::env::split_paths(&existing_path)),
    )
    .unwrap();
    let suite = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/packrat-replay-suite.sh");
    let run = || {
        Command::new("bash")
            .arg(&suite)
            .arg(&manifest)
            .current_dir("/")
            .env("PATH", &path)
            .output()
            .unwrap()
    };

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
