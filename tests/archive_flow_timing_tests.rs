#[path = "support/http.rs"]
mod support;

use packrat_tui::analysis::alert_center::AlertCenter;
use packrat_tui::net::packet::{CaptureMetadata, CaptureTimestamp, TimestampResolution};
use packrat_tui::storage::packet_archive::PacketArchive;
use serde_json::{Value, json};
use std::process::Command;

#[test]
fn archive_flow_timing_uses_adjacent_cited_frames_in_each_direction() {
    let root = tempfile::tempdir().unwrap();
    let archive_path = root.path().join("archive");
    let log = root.path().join("alerts.jsonl");
    let mut center = AlertCenter::default();
    center.record(8, "IDS", "MEDIUM", "Saved lead", "private detail");
    let mut alert = center.items.remove(0);
    alert.capture_id = Some("scope-a".into());
    alert.packet_refs = (1..=9).rev().collect();
    std::fs::write(
        &log,
        json!({"schema_version":1,"record_type":"alert","session_id":"session-a","alert":alert})
            .to_string(),
    )
    .unwrap();

    let packet = |frame, time: Option<u64>, reverse| {
        // Legacy floating-point time deliberately does not describe the retained capture clock.
        let mut packet = support::tcp(frame, 100, 0x18, b"private payload", reverse);
        let length = packet.bytes.len() as u32;
        packet.capture = Some(CaptureMetadata {
            timestamp: time.map(|ticks| CaptureTimestamp {
                ticks,
                resolution: TimestampResolution::Decimal(9),
                offset_seconds: 1_800_000_000,
            }),
            captured_length: length,
            wire_length: length,
            link_type: 1,
            section_id: 0,
            interface_id: 0,
            interface_name: None,
            comments: Vec::new(),
        });
        packet
    };
    let mut archive = PacketArchive::open(&archive_path).unwrap();
    archive
        .append_scoped(
            "scope-a",
            &[
                packet(1, Some(0), false),
                packet(2, Some(1), false),
                packet(3, Some(500), true),
                packet(4, Some(1), false),
                packet(5, Some(0), false),
                packet(6, None, false),
                packet(7, Some(10), false),
                packet(8, Some(13), false),
                packet(10, Some(50), false), // Not cited.
            ],
        )
        .unwrap();
    drop(archive);
    let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&archive_path)
        .arg("--alert-flow-summary")
        .arg(&log)
        .args(["session-a", "1", "--capture-id", "scope-a"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("private"));
    let report: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["referenced_frames"], 9);
    assert_eq!(report["missing_frames"], 1);
    let flows = report["directional_flows"].as_array().unwrap();
    assert_eq!(flows.len(), 2);
    let forward = flows
        .iter()
        .find(|flow| flow["contains_trigger_frame"] == true)
        .unwrap();
    assert_eq!(
        forward["cited_timing"],
        json!({"timestamped_frames":6,"missing_timestamp_frames":1,"forward_gaps":2,
            "tied_timestamps":1,"backwards_timestamps":1,"min_forward_gap_secs":1e-9,
            "max_forward_gap_secs":3e-9,"mean_forward_gap_secs":2e-9})
    );
    let reverse = flows
        .iter()
        .find(|flow| flow["contains_trigger_frame"] == false)
        .unwrap();
    assert_eq!(reverse["cited_timing"]["timestamped_frames"], 1);
    assert_eq!(reverse["cited_timing"]["forward_gaps"], 0);
    assert!(reverse["cited_timing"]["mean_forward_gap_secs"].is_null());
}
