#[path = "support/packets.rs"]
mod packets;

use packrat_tui::analysis::alert_center::AlertCenter;
use packrat_tui::net::packet::CaptureMetadata;
use packrat_tui::storage::packet_archive::PacketArchive;
use serde_json::{Value, json};
use std::process::Command;

#[test]
fn archived_handshake_candidates_account_for_data_on_syn_and_syn_ack() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive");
    let log = root.path().join("alerts.jsonl");
    let mut alerts = AlertCenter::default();
    alerts.record(1, "IDS", "HIGH", "Saved finding", "fixture");
    let mut alert = alerts.items.remove(0);
    alert.capture_id = Some("scope-a".into());
    alert.packet_refs = (1..=9).collect();
    std::fs::write(&log,
        json!({"schema_version":1,"record_type":"alert","session_id":"session-a","alert":alert}).to_string(),
    ).unwrap();

    let packet = |no, reverse, flags, sequence, ack: u32, payload: &[u8], missing_bytes| {
        let mut packet = packets::tcp(no, sequence, flags, payload);
        packet.bytes[42..46].copy_from_slice(&ack.to_be_bytes());
        if reverse {
            for index in 0..4 { packet.bytes.swap(26 + index, 30 + index); }
            for index in 0..2 { packet.bytes.swap(34 + index, 36 + index); }
        }
        let wire_length = packet.bytes.len();
        packet.bytes.truncate(wire_length - missing_bytes);
        packet.capture = Some(CaptureMetadata {
            timestamp: None, captured_length: packet.bytes.len() as u32, wire_length: wire_length as u32,
            link_type: 1, section_id: 0, interface_id: 0, interface_name: None, comments: Vec::new(),
        });
        packet
    };
    let mut archive = PacketArchive::open(&path).unwrap();
    archive.append_scoped("scope-a", &[
        packet(1, false, 0x02, u32::MAX - 1, 0, b"data", 3),
        packet(2, false, 0x02, u32::MAX - 1, 0, b"", 0),
        packet(3, true, 0x12, 200, 3, b"yes", 0),
        packet(4, false, 0x10, 3, 204, b"", 0),
        packet(5, false, 0x10, 3, 205, b"", 0),
        packet(6, true, 0x12, 300, 4, b"", 0),
        packet(7, false, 0x02, 100, 0, b"hi", 0),
        packet(8, true, 0x12, 400, 101, b"", 0),
        packet(9, false, 0x10, 101, 401, b"hi", 0),
    ]).unwrap();
    drop(archive);
    let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&path).arg("--alert-flow-summary").arg(&log)
        .args(["session-a", "1", "--capture-id", "scope-a"]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["truncated_frames"], 1);
    assert_eq!(result["tcp_syn_ack_matches"], json!([
        {"syn_ack_frame":3,"prior_syn_candidates":1,"latest_candidate_syn_frame":1,
         "later_ack_candidates":1,"earliest_candidate_ack_frame":4},
        {"syn_ack_frame":8,"prior_syn_candidates":1,"latest_candidate_syn_frame":7,
         "later_ack_candidates":1,"earliest_candidate_ack_frame":9}
    ]));
}
