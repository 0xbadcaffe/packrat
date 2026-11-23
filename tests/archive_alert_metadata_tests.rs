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
    assert!(report.get("trigger_frame_number").is_none());
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
    let records: Vec<_> = [(1, 2), (2, 5), (3, 6), (4, 0)].into_iter().map(|(id, trigger)| {
        let mut alert = alert.clone();
        alert.id = id;
        alert.packet_no = trigger;
        alert.last_packet = trigger;
        json!({"schema_version":1,"record_type":"alert","session_id":"session-a","alert":alert}).to_string()
    }).collect();
    std::fs::write(&log, records.join("\n")).unwrap();
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

    let run = |id| {
        let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
            .arg(&path).arg("--alert-flow-summary").arg(&log).args(["session-a", id, "--capture-id", "scope-a"])
            .output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains("private") && !text.contains("203.0.113.77"));
        serde_json::from_str::<Value>(&text).unwrap()
    };
    let report = run("1");
    assert_eq!(report["record_type"], "alert_flow_summary");
    assert_eq!(report["trigger_frame"], json!({"frame_number":2,"status":"complete","transport_header_observed":true}));
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
        let matched_path = flow["vlan_id"] == 10 && flow["interface_id"] == 3;
        assert_eq!(flow["contains_trigger_frame"], matched_path && flow["source"] == "10.0.0.2:80");
        if matched_path {
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
    for (id, expected) in [
        ("2", json!({"frame_number":5,"status":"missing","transport_header_observed":false})),
        ("3", json!({"frame_number":6,"status":"truncated","transport_header_observed":false})),
        ("4", Value::Null),
    ] {
        let report = run(id);
        assert_eq!(report["trigger_frame"], expected);
        assert!(report["directional_flows"].as_array().unwrap().iter()
            .all(|flow| flow["contains_trigger_frame"] == false));
    }
}

#[test]
fn alert_flow_summary_distinguishes_full_vlan_stacks_and_bounds_depth() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive");
    let log = root.path().join("alerts.jsonl");
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "HIGH", "Saved alert", "fixture");
    let mut alert = center.items.remove(0);
    alert.capture_id = Some("scope-a".into());
    alert.packet_refs = (1..=5).collect();
    std::fs::write(&log,
        json!({"schema_version":1,"record_type":"alert","session_id":"session-a","alert":alert}).to_string(),
    ).unwrap();

    let make = |no, reverse, tags: &[(u16, u16)]| {
        let mut packet = packets::tcp(no, 100, if reverse { 0x12 } else { 0x02 }, b"");
        if reverse {
            for index in 0..4 { packet.bytes.swap(26 + index, 30 + index); }
            for index in 0..2 { packet.bytes.swap(34 + index, 36 + index); }
        }
        packet.bytes.splice(12..12, tags.iter().flat_map(|(tpid, tci)| {
            tpid.to_be_bytes().into_iter().chain(tci.to_be_bytes())
        }));
        let length = packet.bytes.len() as u32;
        packet.capture = Some(CaptureMetadata {
            timestamp: None, captured_length: length, wire_length: length, link_type: 1,
            section_id: 2, interface_id: 3, interface_name: None, comments: Vec::new(),
        });
        packet
    };
    let mut archive = PacketArchive::open(&path).unwrap();
    archive.append_scoped("scope-a", &[
        make(1, false, &[(0x88a8, 10), (0x8100, 20), (0x8100, 30)]),
        make(2, true, &[(0x88a8, 10), (0x8100, 20 | 0xb000), (0x8100, 30)]),
        make(3, true, &[(0x88a8, 10), (0x8100, 21), (0x8100, 30)]),
        make(4, true, &[(0x9100, 10), (0x8100, 20), (0x8100, 30)]),
        make(5, true, &[(0x8100, 10); 17]),
    ]).unwrap();
    drop(archive);

    let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&path).arg("--alert-flow-summary").arg(&log).args(["session-a", "1", "--capture-id", "scope-a"])
        .output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["max_vlan_tags"], 16);
    assert_eq!(report["retained_frames_without_flow"], 1);
    let flows = report["directional_flows"].as_array().unwrap();
    assert_eq!(flows.len(), 4);
    let matching_stack = json!([{"tpid":0x88a8,"vid":10},{"tpid":0x8100,"vid":20},{"tpid":0x8100,"vid":30}]);
    assert_eq!(flows.iter().filter(|flow| flow["vlan_stack"] == matching_stack).count(), 2);
    for flow in flows {
        assert_eq!(flow["outer_vlan_id"], 10);
        assert_eq!(flow["vlan_id"], 30);
        assert_eq!(flow["reverse_evidence_frames"], u8::from(flow["vlan_stack"] == matching_stack));
    }
}
