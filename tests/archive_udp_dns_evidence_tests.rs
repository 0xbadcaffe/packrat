use packrat_tui::analysis::alert_center::AlertCenter;
use packrat_tui::net::{packet::{CaptureMetadata, Packet}, parser::parse_ethernet};
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
    let mut packet = parse_ethernet(&wire, no, no as f64);
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
        {"reply_frame":7,"query_candidate_frames":[1,2]},
        {"reply_frame":8,"query_candidate_frames":[]},
        {"reply_frame":10,"query_candidate_frames":[]}
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
    alert.packet_refs = vec![1, 2, 3, 4];
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
    archive
        .append_scoped(
            SCOPE,
            &[
                dns_frame(1, 42, b"PrivateName", false, 10, 1),
                dns_frame(2, 42, b"PrivateName", false, 10, 1),
                dns_frame(3, 42, b"PrivateName", true, 10, 1),
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
        json!({"complete":3,"missing":1}),
        "{finding}"
    );
    assert_eq!(finding["flow_context_status"], "checked");
    assert_eq!(
        finding["flow_context"],
        json!({"directional_flows":2,"tcp_syn_ack_matches":0,"udp_dns_replies":1,
               "udp_dns_replies_with_query_candidates":1,"udp_dns_ambiguous_replies":1})
    );
}
