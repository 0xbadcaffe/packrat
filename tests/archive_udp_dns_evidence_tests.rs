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
