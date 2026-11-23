#[path = "support/packets.rs"]
mod packets;

use std::process::Command;

use packrat_tui::analysis::alert_center::{AlertCenter, AlertFlow, AlertTransport};
use packrat_tui::analysis::packet_fields::extract_fields;
use packrat_tui::net::packet::CaptureMetadata;
use packrat_tui::storage::packet_archive::PacketArchive;
use serde_json::{Value, json};

#[test]
fn archive_links_syn_acks_only_to_preceding_reverse_syn_sequences_on_the_same_path() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive");
    let log = root.path().join("alerts.jsonl");
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "HIGH", "Saved alert", "fixture");
    let mut alert = center.items.remove(0);
    alert.capture_id = Some("scope-a".into());
    alert.packet_refs = (1..=10).collect();
    std::fs::write(&log,
        json!({"schema_version":1,"record_type":"alert","session_id":"session-a","alert":alert}).to_string(),
    ).unwrap();
    let packet = |no, reverse, flags, sequence, ack: u32, vlan, interface_id| {
        let mut packet = packets::tcp(no, sequence, flags, b"");
        packet.bytes[42..46].copy_from_slice(&ack.to_be_bytes());
        if reverse {
            for index in 0..4 { packet.bytes.swap(26 + index, 30 + index); }
            for index in 0..2 { packet.bytes.swap(34 + index, 36 + index); }
        }
        packet.bytes.splice(12..12, [0x81, 0, 0, vlan]);
        let length = packet.bytes.len() as u32;
        packet.capture = Some(CaptureMetadata {
            timestamp: None, captured_length: length, wire_length: length, link_type: 1,
            section_id: 2, interface_id, interface_name: None, comments: Vec::new(),
        });
        packet
    };
    let mut archive = PacketArchive::open(&path).unwrap();
    archive.append_scoped("scope-a", &[
        packet(1, false, 0x02, u32::MAX, 0, 10, 3),
        packet(2, false, 0x02, u32::MAX, 0, 10, 3),
        packet(3, true, 0x12, 100, 0, 10, 3),
        packet(4, true, 0x12, 100, 8, 10, 3),
        packet(5, false, 0x02, 7, 0, 10, 3),
        packet(6, true, 0x12, 100, 0, 20, 3),
        packet(7, true, 0x12, 100, 0, 10, 4),
        packet(8, false, 0x12, 100, 0, 10, 3),
        packet(9, true, 0x16, 100, 0, 10, 3),
        packet(10, true, 0x12, 101, 8, 10, 3),
    ]).unwrap();
    drop(archive);
    let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&path).arg("--alert-flow-summary").arg(&log).args(["session-a", "1", "--capture-id", "scope-a"])
        .output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["tcp_syn_ack_matches"], json!([
        {"syn_ack_frame":3,"prior_syn_candidates":2,"latest_candidate_syn_frame":2},
        {"syn_ack_frame":10,"prior_syn_candidates":1,"latest_candidate_syn_frame":5}
    ]));
    assert!(report["limitation"].as_str().unwrap().contains("not a completed handshake"));
}

#[test]
fn truncated_payloads_corroborate_complete_headers_without_claiming_complete_evidence() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive");
    let log = root.path().join("alerts.jsonl");
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "HIGH", "Saved alert", "fixture");
    let mut alert = center.items.remove(0);
    alert.capture_id = Some("scope-a".into());
    alert.packet_refs = (1..=6).collect();
    alert.flow = Some(AlertFlow {
        transport: AlertTransport::Tcp,
        source: "10.0.0.1:40000".parse().unwrap(),
        destination: "10.0.0.2:80".parse().unwrap(),
    });
    std::fs::write(&log,
        json!({"schema_version":1,"record_type":"alert","session_id":"session-a","alert":alert}).to_string(),
    ).unwrap();

    let truncate = |mut packet: packrat_tui::net::packet::Packet, len: u32| {
        let wire_length = packet.bytes.len() as u32;
        packet.bytes.truncate(len as usize);
        packet.capture = Some(CaptureMetadata {
            timestamp: None, captured_length: len, wire_length, link_type: 1,
            section_id: 2, interface_id: 3, interface_name: None, comments: Vec::new(),
        });
        packet
    };
    let tcp = truncate(packets::tcp(1, 100, 0x02, &[0; 32]), 54);
    let mut wrong_wire_length = tcp.clone();
    wrong_wire_length.no = 2;
    wrong_wire_length.capture.as_mut().unwrap().wire_length -= 1;

    let mut ipv6_udp = packets::tcp(3, 100, 0x02, b"");
    let mut headers = [0; 56];
    headers[0] = 0x60;
    headers[4..6].copy_from_slice(&48_u16.to_be_bytes());
    headers[6] = 60; // Destination Options, then UDP.
    headers[23] = 1;
    headers[39] = 2;
    headers[40] = 17;
    headers[48..54].copy_from_slice(&[0x9c, 0x40, 0x01, 0xbb, 0x00, 40]);
    ipv6_udp.bytes[12..14].copy_from_slice(&[0x86, 0xdd]);
    ipv6_udp.bytes.truncate(14);
    ipv6_udp.bytes.extend_from_slice(&headers);
    ipv6_udp.bytes.extend_from_slice(&[0; 32]);
    let mut cut_udp_header = truncate(ipv6_udp.clone(), 69);
    cut_udp_header.no = 4;
    let mut wrong_udp_length = truncate(ipv6_udp.clone(), 70);
    wrong_udp_length.no = 5;
    wrong_udp_length.bytes[67] = 41;
    let mut missing_metadata = truncate(ipv6_udp.clone(), 70);
    missing_metadata.no = 6;
    missing_metadata.capture = None;
    let udp = truncate(ipv6_udp, 70);
    assert!(extract_fields(&tcp).iter().any(|field| field.path == "tcp.seq"));
    assert!(extract_fields(&udp).iter().any(|field| field.path == "udp.length"));
    assert!(!extract_fields(&missing_metadata).iter().any(|field| field.path == "udp.length"));

    let mut archive = PacketArchive::open(&path).unwrap();
    archive.append_scoped("scope-a", &[tcp, wrong_wire_length, udp, cut_udp_header, wrong_udp_length, missing_metadata]).unwrap();
    drop(archive);
    let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&path).arg("--alert-flow-summary").arg(&log).args(["session-a", "1", "--capture-id", "scope-a"])
        .output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["trigger_tuple_status"], "matches_wire");
    assert_eq!(report["trigger_frame"], json!({"frame_number":1,"status":"truncated","transport_header_observed":true}));
    assert_eq!(report["truncated_frames"], 5);
    assert_eq!(report["unassigned_frames"].as_array().unwrap().iter()
        .map(|frame| frame["frame_number"].as_u64().unwrap()).collect::<Vec<_>>(), [2, 4, 5, 6]);
    let flows = report["directional_flows"].as_array().unwrap();
    assert_eq!(flows.len(), 2);
    assert!(flows.iter().any(|flow| flow["protocol"] == "udp" && flow["frames"] ==
        json!([{"frame_number":3,"status":"truncated"}])));
}

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
    let records: Vec<_> = [(1, 2), (2, 5), (3, 6), (4, 0), (5, 2), (6, 2)].into_iter().map(|(id, trigger)| {
        let mut alert = alert.clone();
        alert.id = id;
        alert.packet_no = trigger;
        alert.last_packet = trigger;
        alert.flow = (id != 6).then(|| AlertFlow {
            transport: AlertTransport::Tcp,
            source: if id == 5 { "203.0.113.77:80" } else { "10.0.0.2:80" }.parse().unwrap(),
            destination: "10.0.0.1:40000".parse().unwrap(),
        });
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
    assert_eq!(report["trigger_tuple_status"], "matches_wire");
    assert_eq!(report["trigger_frame"], json!({"frame_number":2,"status":"complete","transport_header_observed":true}));
    assert_eq!(report["referenced_frames"], 7);
    assert_eq!(report["missing_frames"], 1);
    assert_eq!(report["truncated_frames"], 1);
    assert_eq!(report["unreadable_frames"], 1);
    assert_eq!(report["retained_frames_without_flow"], 1);
    assert_eq!(report["unassigned_frames"], json!([
        {"frame_number":5,"status":"missing"},
        {"frame_number":6,"status":"truncated"},
        {"frame_number":7,"status":"unreadable"}
    ]));
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
                assert_eq!(flow["frames"], json!([{"frame_number":1,"status":"complete"}]));
            } else {
                assert_eq!(flow["source"], "10.0.0.2:80");
                assert_eq!(flow["syn_ack_frames"], 1);
                assert_eq!(flow["frames"], json!([{"frame_number":2,"status":"complete"}]));
            }
        } else {
            assert_eq!(flow["reverse_evidence_frames"], 0);
            assert_eq!(flow["reset_frames"], 1);
            let number = if flow["vlan_id"] == 20 { 3 } else { 4 };
            assert_eq!(flow["frames"], json!([{"frame_number":number,"status":"complete"}]));
        }
    }
    for (id, expected) in [
        ("2", json!({"frame_number":5,"status":"missing","transport_header_observed":false})),
        ("3", json!({"frame_number":6,"status":"truncated","transport_header_observed":false})),
        ("4", Value::Null),
    ] {
        let report = run(id);
        assert_eq!(report["trigger_frame"], expected);
        assert_eq!(report["trigger_tuple_status"], "trigger_header_unavailable");
        assert!(report["directional_flows"].as_array().unwrap().iter()
            .all(|flow| flow["contains_trigger_frame"] == false));
    }
    assert_eq!(run("5")["trigger_tuple_status"], "differs_from_wire");
    assert_eq!(run("6")["trigger_tuple_status"], "not_recorded");
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
    assert_eq!(report["unassigned_frames"], json!([{"frame_number":5,"status":"complete"}]));
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

#[test]
fn archive_does_not_assign_flow_identity_to_incomplete_ip_fragments() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive");
    let log = root.path().join("alerts.jsonl");
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "HIGH", "Saved alert", "fixture");
    let mut alert = center.items.remove(0);
    alert.capture_id = Some("scope-a".into());
    alert.packet_refs = (1..=4).collect();
    alert.flow = Some(AlertFlow {
        transport: AlertTransport::Tcp,
        source: "10.0.0.1:40000".parse().unwrap(),
        destination: "10.0.0.2:80".parse().unwrap(),
    });
    std::fs::write(&log,
        json!({"schema_version":1,"record_type":"alert","session_id":"session-a","alert":alert}).to_string(),
    ).unwrap();

    let mut v4 = packets::tcp(1, 100, 0x18, b"data");
    v4.bytes[20..22].copy_from_slice(&0x2000_u16.to_be_bytes());
    let make_v6 = |no, fragment_field: u16| {
        let mut packet = packets::tcp(no, 100, 0x18, b"data");
        let mut ip6_with_fragment = [0u8; 48];
        ip6_with_fragment[0] = 0x60;
        ip6_with_fragment[4..6].copy_from_slice(&32_u16.to_be_bytes());
        ip6_with_fragment[6] = 44;
        ip6_with_fragment[8..24].copy_from_slice(&"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        ip6_with_fragment[24..40].copy_from_slice(&"2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
        ip6_with_fragment[40] = 6;
        ip6_with_fragment[42..44].copy_from_slice(&fragment_field.to_be_bytes());
        packet.bytes[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        packet.bytes.splice(14..34, ip6_with_fragment);
        packet
    };
    let mut frames = [v4, make_v6(2, 1), make_v6(3, 8), make_v6(4, 0)];
    for packet in &mut frames {
        let length = packet.bytes.len() as u32;
        packet.capture = Some(CaptureMetadata {
            timestamp: None, captured_length: length, wire_length: length, link_type: 1,
            section_id: 0, interface_id: 0, interface_name: None, comments: Vec::new(),
        });
    }
    for packet in &frames[..2] {
        assert!(packrat_tui::analysis::packet_fields::extract_fields(packet)
            .iter().any(|field| field.path == "tcp.dstport"));
    }
    let mut archive = PacketArchive::open(&path).unwrap();
    archive.append_scoped("scope-a", &frames).unwrap();
    drop(archive);
    let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&path).arg("--alert-flow-summary").arg(&log).args(["session-a", "1", "--capture-id", "scope-a"])
        .output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["trigger_tuple_status"], "trigger_header_unavailable");
    assert_eq!(report["retained_frames_without_flow"], 3);
    assert_eq!(report["unassigned_frames"], json!([
        {"frame_number":1,"status":"complete"},
        {"frame_number":2,"status":"complete"},
        {"frame_number":3,"status":"complete"}
    ]));
    let flows = report["directional_flows"].as_array().unwrap();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0]["source"], "[2001:db8::1]:40000");
    assert_eq!(flows[0]["frames"], json!([{"frame_number":4,"status":"complete"}]));
}
