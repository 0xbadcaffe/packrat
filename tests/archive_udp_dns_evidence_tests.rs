use packrat_tui::analysis::alert_center::AlertCenter;
use packrat_tui::net::{packet::{CaptureMetadata, CaptureTimestamp, Packet, TimestampResolution}, parser::parse_ethernet};
use packrat_tui::storage::packet_archive::PacketArchive;
use serde_json::{Value, json};
use std::process::Command;

fn dns_frame(no: u64, id: u16, label: &[u8], reply: bool, vlan: u8, qtype: u16) -> Packet {
    let mut message = id.to_be_bytes().to_vec();
    message.extend([if reply { 0x81 } else { 1 }, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    message.push(label.len() as u8);
    message.extend(label);
    message.extend(b"\x04test\0");
    message.extend(qtype.to_be_bytes());
    message.extend([0, 1]);
    let udp_len = 8 + message.len() as u16;
    let mut wire = vec![0; 46];
    wire[12..18].copy_from_slice(&[0x81, 0, 0, vlan, 0x08, 0]);
    wire[18] = 0x45;
    wire[20..22].copy_from_slice(&(20 + udp_len).to_be_bytes());
    wire[26..28].copy_from_slice(&[64, 17]);
    let (client, resolver) = ([192, 0, 2, 1], [192, 0, 2, 53]);
    let ((src, dst), (src_port, dst_port)): (_, (u16, u16)) =
        if reply { ((resolver, client), (53, 40000)) } else { ((client, resolver), (40000, 53)) };
    wire[30..34].copy_from_slice(&src);
    wire[34..38].copy_from_slice(&dst);
    wire[38..40].copy_from_slice(&src_port.to_be_bytes());
    wire[40..42].copy_from_slice(&dst_port.to_be_bytes());
    wire[42..44].copy_from_slice(&udp_len.to_be_bytes());
    wire.extend(message);
    captured_frame(no, &wire)
}

fn captured_frame(no: u64, wire: &[u8]) -> Packet {
    let mut packet = parse_ethernet(wire, no, no as f64);
    packet.capture = Some(CaptureMetadata {
        timestamp: None, captured_length: wire.len() as u32, wire_length: wire.len() as u32,
        link_type: 1, section_id: 0, interface_id: 0, interface_name: None, comments: Vec::new(),
    });
    packet
}

#[test]
fn dns_reply_candidates_match_only_prior_questions_on_the_reverse_wire_path() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive");
    let log = root.path().join("alerts.jsonl");
    let mut alerts = AlertCenter::default();
    alerts.record(7, "IDS", "MEDIUM", "Saved finding", "fixture");
    let mut alert = alerts.items.remove(0);
    alert.capture_id = Some("scope-a".into());
    alert.packet_refs = (1..=10).collect();
    std::fs::write(&log,
        json!({"schema_version":1,"record_type":"alert","session_id":"session-a","alert":alert}).to_string(),
    ).unwrap();

    let make = |no, reply, vlan| dns_frame(no, 17, b"PrivateName", reply, vlan, 1);
    let mut another_interface = make(8, true, 10);
    another_interface.capture.as_mut().unwrap().interface_id = 1;
    let mut partial = make(9, true, 10);
    partial.bytes.pop();
    partial.capture.as_mut().unwrap().captured_length -= 1;
    let mut delayed = make(10, true, 10);
    delayed.timestamp = 45.0;
    let mut archive = PacketArchive::open(&path).unwrap();
    archive.append_scoped("scope-a", &[
        make(1, false, 10), dns_frame(2, 17, b"privatename", false, 10, 1),
        dns_frame(3, 17, b"other", false, 10, 1), dns_frame(4, 18, b"privatename", false, 10, 1),
        make(5, false, 20), dns_frame(6, 17, b"privatename", false, 10, 28),
        make(7, true, 10), another_interface, partial, delayed,
    ]).unwrap();
    drop(archive);
    let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&path).arg("--alert-flow-summary").arg(&log)
        .args(["session-a", "1", "--capture-id", "scope-a"]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.to_ascii_lowercase().contains("privatename"));
    let report: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["truncated_frames"], 1);
    assert_eq!(report["udp_dns_reply_candidates"], json!([
        {"reply_frame":7,"query_candidate_frames":[1,2],"timestamp_basis":"legacy_packet_time"},
        {"reply_frame":8,"query_candidate_frames":[],"timestamp_basis":"legacy_packet_time"},
        {"reply_frame":10,"query_candidate_frames":[],"timestamp_basis":"legacy_packet_time"}
    ]));
}

fn attach_capture_time(packet: &mut Packet, ticks: u64) {
    packet.capture.as_mut().unwrap().timestamp = Some(CaptureTimestamp {
        ticks,
        resolution: TimestampResolution::Decimal(9),
        offset_seconds: 1_800_000_000,
    });
}

#[test]
fn dns_summary_distinguishes_missing_legacy_time_from_capture_clock_zero() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive");
    let log = root.path().join("alerts.jsonl");
    let mut alerts = AlertCenter::default();
    alerts.record(6, "IDS", "MEDIUM", "Saved finding", "fixture");
    let mut alert = alerts.items.remove(0);
    alert.capture_id = Some("scope-a".into());
    alert.packet_refs = (1..=6).collect();
    std::fs::write(
        &log,
        json!({"schema_version":1,"record_type":"alert","session_id":"session-a","alert":alert}).to_string(),
    ).unwrap();

    let mut archive = PacketArchive::open(&path).unwrap();
    for (no, reply, vlan, legacy, exact) in [
        (1, false, 10, 0.0, None),
        (2, true, 10, 0.0, None),
        (3, false, 20, 500.0, Some(0)),
        (4, true, 20, 600.0, Some(1_000_000)),
        (5, false, 30, 7.0, None),
        (6, true, 30, 8.0, None),
    ] {
        let mut packet = dns_frame(no, 17, b"sample", reply, vlan, 1);
        packet.timestamp = legacy;
        if let Some(ticks) = exact {
            attach_capture_time(&mut packet, ticks);
            packet.capture.as_mut().unwrap().timestamp.as_mut().unwrap().offset_seconds = 0;
        }
        archive.append_scoped("scope-a", &[packet]).unwrap();
    }
    drop(archive);

    let run = |action| {
        let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
            .arg(&path).arg(action).arg(&log)
            .args(["session-a", "1", "--capture-id", "scope-a"]).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    let summary = run("--alert-flow-summary");
    assert_eq!(summary["udp_dns_reply_candidates"], json!([
        {"reply_frame":2,"query_candidate_frames":[],"timestamp_basis":"unavailable"},
        {"reply_frame":4,"query_candidate_frames":[3],"timestamp_basis":"capture_clock"},
        {"reply_frame":6,"query_candidate_frames":[5],"timestamp_basis":"legacy_packet_time"}
    ]));
    let flows = summary["directional_flows"].as_array().unwrap();
    assert!(flows.iter().filter(|flow| flow["vlan_id"] == 10)
        .all(|flow| flow["first_seen"].is_null() && flow["last_seen"].is_null()));
    let metadata = run("--alert-packet-metadata");
    let timestamps: Vec<_> = metadata["frames"].as_array().unwrap().iter()
        .map(|frame| frame["packet"]["timestamp"].as_f64()).collect();
    assert_eq!(timestamps, [None, None, Some(0.0), Some(0.001), Some(7.0), Some(8.0)]);
}

#[test]
fn dns_candidates_use_capture_time_at_the_window_boundary_without_mixing_clocks() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive");
    let log = root.path().join("alerts.jsonl");
    let mut alerts = AlertCenter::default();
    alerts.record(7, "IDS", "MEDIUM", "Saved finding", "fixture");
    let mut alert = alerts.items.remove(0);
    alert.capture_id = Some("scope-a".into());
    alert.packet_refs = (1..=7).collect();
    std::fs::write(&log,
        json!({"schema_version":1,"record_type":"alert","session_id":"session-a","alert":alert}).to_string(),
    ).unwrap();

    let frames: Vec<_> = [
        (1, false, Some(100)),
        (2, false, None),
        (3, true, Some(30_000_000_099)),
        (4, true, Some(30_000_000_100)),
        (5, true, Some(30_000_000_101)),
        (6, true, Some(99)),
        (7, true, None),
    ].into_iter().map(|(frame, reply, capture_ticks)| {
        let mut packet = dns_frame(frame, 17, b"PrivateName", reply, 10, 1);
        if let Some(ticks) = capture_ticks { attach_capture_time(&mut packet, ticks); }
        packet
    }).collect();
    let mut archive = PacketArchive::open(&path).unwrap();
    archive.append_scoped("scope-a", &frames).unwrap();
    drop(archive);
    let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&path).arg("--alert-flow-summary").arg(&log)
        .args(["session-a", "1", "--capture-id", "scope-a"]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.to_ascii_lowercase().contains("privatename"));
    let report: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["udp_dns_reply_candidates"], json!([
        {"reply_frame":3,"query_candidate_frames":[1],"timestamp_basis":"capture_clock"},
        {"reply_frame":4,"query_candidate_frames":[1],"timestamp_basis":"capture_clock"},
        {"reply_frame":5,"query_candidate_frames":[],"timestamp_basis":"capture_clock"},
        {"reply_frame":6,"query_candidate_frames":[],"timestamp_basis":"capture_clock"},
        {"reply_frame":7,"query_candidate_frames":[2],"timestamp_basis":"legacy_packet_time"}
    ]));
}

#[cfg(target_os = "linux")]
#[test]
fn backlog_review_counts_correlated_dns_from_real_archive_and_rotated_log() {
    use std::{env, fs, path::Path};

    const SCOPE: &str = "00000000000000000000000000000001";
    let root = tempfile::tempdir().unwrap();
    let archive_path = root.path().join("archive");
    let active = root.path().join("alerts.jsonl");
    let previous = root.path().join("previous.jsonl");

    let mut alerts = AlertCenter::default();
    alerts.record(4, "IDS", "HIGH", "Private title", "Private detail");
    let mut alert = alerts.items.remove(0);
    alert.capture_id = Some(SCOPE.into());
    alert.packet_refs = vec![1, 2, 3, 4, 5];
    fs::write(&active, "").unwrap();
    fs::write(
        &previous,
        format!(
            "{}\n",
            json!({"schema_version":1,"record_type":"alert","session_id":"session-a","alert":alert})
        ),
    )
    .unwrap();

    let mut archive = PacketArchive::open(&archive_path).unwrap();
    let mut non_ip_frame = [0; 60];
    non_ip_frame[12..14].copy_from_slice(&[0x88, 0xb5]);
    let timed_dns = |frame, reply| {
        let mut packet = dns_frame(frame, 42, b"PrivateName", reply, 10, 1);
        attach_capture_time(&mut packet, frame);
        packet
    };
    archive
        .append_scoped(
            SCOPE,
            &[
                timed_dns(1, false),
                timed_dns(2, false),
                timed_dns(3, true),
                captured_frame(4, &non_ip_frame),
            ],
        )
        .unwrap();
    drop(archive);

    let executable = Path::new(env!("CARGO_BIN_EXE_packrat-archive"));
    let path = env::join_paths(
        std::iter::once(executable.parent().unwrap().to_owned())
            .chain(env::split_paths(&env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/packrat-review-backlog.sh");
    let output = Command::new("bash")
        .arg(script)
        .args(["--review-scope", "session-a", SCOPE, "--flow-context"])
        .arg(&archive_path)
        .arg(&active)
        .arg(&previous)
        .env("PATH", path)
        .env("PACKRAT_BACKLOG_TIMEOUT", "30")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.to_ascii_lowercase().contains("private"));
    assert!(!text.contains("192.0.2."));
    let report: Value = serde_json::from_str(&text).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding["packet_evidence_status"], "partial");
    assert_eq!(
        finding["evidence_availability"],
        json!({"complete":4,"missing":1}),
        "{finding}"
    );
    assert_eq!(finding["flow_context_status"], "checked");
    assert_eq!(
        finding["flow_context"],
        json!({"directional_flows":2,"tcp_syn_ack_matches":0,"udp_dns_replies":1,
               "tcp_syn_ack_with_later_ack_candidates":0,"tcp_syn_ack_without_later_ack_candidates":0,
               "tcp_syn_ack_ambiguous_candidates":0,"tcp_flag_status":"no_tcp_headers",
               "retained_flow_frames":3,"retained_frames_without_flow":1,
               "trigger_frame_status":"complete","trigger_transport_header_observed":false,
               "trigger_tuple_status":"not_recorded",
               "timing_status":"reported","cited_timing":{"timestamped_frames":3,"missing_timestamp_frames":0,
                    "forward_gaps":1,"tied_timestamps":0,"backwards_timestamps":0,"directions_with_forward_gaps":1},
               "udp_dns_replies_with_query_candidates":1,"udp_dns_ambiguous_replies":1})
    );
}
