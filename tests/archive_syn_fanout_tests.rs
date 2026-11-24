#[path = "support/packets.rs"]
mod packets;

use packrat_tui::analysis::alert_center::AlertCenter;
use packrat_tui::net::packet::CaptureMetadata;
use packrat_tui::storage::packet_archive::PacketArchive;
use serde_json::{Value, json};
use std::process::Command;

#[test]
fn cited_syn_fanout_excludes_other_tcp_flags_and_deduplicates_hosts_across_paths() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive");
    let log = root.path().join("alerts.jsonl");
    let capture = "capture-a";
    let mut alerts = AlertCenter::default();
    alerts.record(1, "IDS", "HIGH", "Saved finding", "fixture");
    let mut alert = alerts.items.remove(0);
    alert.capture_id = Some(capture.into());
    alert.packet_refs = (1..=6).collect();
    std::fs::write(
        &log,
        json!({"schema_version":1,"record_type":"alert","session_id":"session-a","alert":alert})
            .to_string(),
    )
    .unwrap();
    let frames: Vec<_> = [
        (1, 1, 443_u16, 0, 0x02),
        (2, 1, 443, 1, 0x02),
        (3, 2, 443, 0, 0x02),
        (4, 3, 22, 0, 0x10),
        (5, 4, 22, 0, 0x12),
        (6, 1, 443, 0, 0x02),
    ]
    .into_iter()
    .map(|(no, host, port, interface_id, flags)| {
        let mut packet = packets::tcp(no, 100, flags, &[]);
        packet.bytes[33] = host;
        packet.bytes[36..38].copy_from_slice(&port.to_be_bytes());
        let length = packet.bytes.len() as u32;
        packet.capture = Some(CaptureMetadata {
            timestamp: None,
            captured_length: length,
            wire_length: length,
            link_type: 1,
            section_id: 0,
            interface_id,
            interface_name: None,
            comments: Vec::new(),
        });
        packet
    })
    .collect();
    let mut archive = PacketArchive::open(&path).unwrap();
    archive.append_scoped(capture, &frames).unwrap();
    drop(archive);

    let output = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&path)
        .arg("--alert-flow-summary")
        .arg(&log)
        .args(["session-a", "1", "--capture-id", capture])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["cited_syn_fanout"],
        json!({"source_hosts":1,"destination_hosts":2,"destination_ports":1,"capture_paths":2})
    );
}
