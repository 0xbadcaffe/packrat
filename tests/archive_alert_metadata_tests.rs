#[path = "support/packets.rs"]
mod packets;

use std::process::Command;

use packrat_tui::analysis::alert_center::AlertCenter;
use packrat_tui::net::packet::CaptureMetadata;
use packrat_tui::storage::packet_archive::PacketArchive;
use serde_json::{Value, json};

#[test]
fn alert_packet_metadata_is_scoped_and_has_no_packet_payload_or_comments() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("archive");
    let log = root.path().join("alerts.jsonl");
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "HIGH", "Saved alert", "private alert detail");
    let mut alert = center.items[0].clone();
    alert.capture_id = Some("scope-a".into());
    alert.packet_refs = vec![1, 2, 3, 4, 5];
    std::fs::write(
        &log,
        json!({"schema_version":1,"record_type":"alert","session_id":"session-a","alert":alert}).to_string(),
    )
    .unwrap();
    let packet = |number, flags, link_type| {
        let mut packet = packets::tcp(number, 100, flags, b"private packet data");
        packet.info = "private decoded data".into();
        let length = packet.bytes.len() as u32;
        packet.capture = Some(CaptureMetadata {
            timestamp: None,
            captured_length: length,
            wire_length: length,
            link_type,
            section_id: 2,
            interface_id: 3,
            interface_name: Some("private interface name".into()),
            comments: vec!["private comment".into()],
        });
        packet
    };
    let mut truncated = packet(2, 0x12, 1);
    truncated.bytes.truncate(45);
    truncated.capture.as_mut().unwrap().captured_length = 45;
    let mut writer = PacketArchive::open(&archive).unwrap();
    writer.append_scoped("scope-a", &[packet(1, 0x02, 1), truncated, packet(3, 0x12, 101)]).unwrap();
    writer.append_scoped("scope-b", &[packet(4, 0x12, 1)]).unwrap();
    let mut malformed = packet(5, 0x12, 1);
    malformed.bytes[46] = 0x10;
    writer.append_scoped("scope-a", &[malformed]).unwrap();
    drop(writer);

    let run = |scope: Option<&str>| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_packrat-archive"));
        cmd.arg(&archive).arg("--alert-packet-metadata").arg(&log).args(["session-a", "1"]);
        if let Some(scope) = scope {
            cmd.args(["--capture-id", scope]);
        }
        cmd.output().unwrap()
    };
    assert!(!run(None).status.success());
    assert!(!run(Some("scope-b")).status.success());
    let output = run(Some("scope-a"));
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("private"));
    let report: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["record_type"], "alert_packet_metadata");
    assert_eq!(report["capture_id"], "scope-a");
    assert_eq!(report["evidence_frame_set_sha256"].as_str().unwrap().len(), 64);
    let frames = report["frames"].as_array().unwrap();
    assert_eq!(frames.len(), 5);
    assert_eq!(frames[0]["packet"]["recorded_source"], "10.0.0.1");
    assert_eq!(frames[0]["packet"]["interface_id"], 3);
    assert_eq!(frames[0]["packet"]["transport"], json!({
        "protocol":"tcp","source_port":40000,"destination_port":80,"tcp_flags":2
    }));
    assert_eq!(frames[1]["status"], "truncated");
    assert!(frames[1]["packet"]["transport"].is_null());
    assert!(frames[2]["packet"]["transport"].is_null());
    assert_eq!(frames[3], json!({"frame_number":4,"status":"missing","packet":null}));
    assert!(frames[4]["packet"]["transport"].is_null());
    assert!(!text.contains("\"bytes\""));
}

#[test]
fn alert_flow_summary_counts_only_cited_headers_in_each_vlan_and_interface() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive");
    let log = root.path().join("alerts.jsonl");
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "HIGH", "Saved alert", "private alert detail");
    let mut alert = center.items.remove(0);
    alert.capture_id = Some("scope-a".into());
    alert.packet_refs = (1..=7).collect();
    std::fs::write(&log,
        json!({"schema_version":1,"record_type":"alert","session_id":"session-a","alert":alert}).to_string(),
    ).unwrap();
    let make = |no, flags, reverse, vlan, interface| {
        let mut packet = packets::tcp(no, 100, flags, b"private payload");
        if reverse {
            for index in 0..4 { packet.bytes.swap(26 + index, 30 + index); }
            for index in 0..2 { packet.bytes.swap(34 + index, 36 + index); }
        }
        packet.bytes.splice(12..12, [0x81, 0, 0, vlan]);
        // The summary must use wire addresses and tags, not the saved display values.
        packet.src = "203.0.113.77".into();
        packet.vlan_id = Some(99);
        let length = packet.bytes.len() as u32;
        packet.capture = Some(CaptureMetadata {
            timestamp: None, captured_length: length, wire_length: length, link_type: 1,
            section_id: 2, interface_id: interface, interface_name: None, comments: Vec::new(),
        });
        packet
    };
    let mut short = make(6, 0x12, true, 10, 3);
    short.bytes.truncate(46);
    short.capture.as_mut().unwrap().captured_length = 46;
    let mut unreadable = make(7, 0x12, true, 10, 3);
    unreadable.capture.as_mut().unwrap().captured_length = 1;
    let mut archive = PacketArchive::open(&path).unwrap();
    archive.append_scoped("scope-b", &[make(5, 0x12, true, 10, 3)]).unwrap();
    archive.append_scoped("scope-a", &[
        make(1, 0x02, false, 10, 3), make(2, 0x12, true, 10, 3),
        make(3, 0x14, true, 20, 3), make(4, 0x14, true, 10, 4), short, unreadable,
        make(8, 0x12, true, 10, 3),
    ]).unwrap();
    drop(archive);

    let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&path).arg("--alert-flow-summary").arg(&log).args(["session-a", "1", "--capture-id", "scope-a"])
        .output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("private") && !text.contains("203.0.113.77"));
    let report: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["record_type"], "alert_flow_summary");
    assert_eq!(report["referenced_frames"], 7);
    assert_eq!(report["missing_frames"], 1);
    assert_eq!(report["truncated_frames"], 1);
    assert_eq!(report["unreadable_frames"], 1);
    assert_eq!(report["retained_frames_without_flow"], 1);
    let flows = report["directional_flows"].as_array().unwrap();
    assert_eq!(flows.len(), 4);
    for flow in flows {
        assert_eq!(flow["section_id"], 2);
        assert_eq!(flow["evidence_frames"], 1);
        if flow["vlan_id"] == 10 && flow["interface_id"] == 3 {
            assert_eq!(flow["reverse_evidence_frames"], 1);
            if flow["source"] == "10.0.0.1:40000" {
                assert_eq!(flow["initial_syn_frames"], 1);
            } else {
                assert_eq!(flow["source"], "10.0.0.2:80");
                assert_eq!(flow["syn_ack_frames"], 1);
            }
        } else {
            assert_eq!(flow["reverse_evidence_frames"], 0);
            assert_eq!(flow["reset_frames"], 1);
        }
    }
}
