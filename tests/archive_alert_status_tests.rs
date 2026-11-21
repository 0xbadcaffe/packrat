use std::io::{Seek, SeekFrom, Write};
use std::process::Command;

use packrat_tui::analysis::alert_center::AlertCenter;
use packrat_tui::net::packet::CaptureMetadata;
use packrat_tui::net::parser::parse_ethernet;
use packrat_tui::storage::packet_archive::PacketArchive;
use serde_json::{Value, json};

#[test]
fn alert_status_distinguishes_missing_partial_and_unreadable_scoped_frames() {
    let directory = tempfile::tempdir().unwrap();
    let archive_path = directory.path().join("archive");
    let mut archive = PacketArchive::open(&archive_path).unwrap();
    let packet = |no, tag, wire_length| {
        let mut frame = parse_ethernet(&[tag; 14], no, 1.0);
        frame.capture = Some(CaptureMetadata {
            timestamp: Some(packrat_tui::net::packet::CaptureTimestamp {
                ticks: 1, resolution: packrat_tui::net::packet::TimestampResolution::Decimal(0),
                offset_seconds: 0,
            }),
            captured_length: 14, wire_length, link_type: 1, interface_id: 0, section_id: 0,
            interface_name: None, comments: Vec::new(),
        });
        frame
    };
    archive.append_scoped("capture-b", &[packet(1, 9, 14), packet(3, 8, 14)]).unwrap();
    archive.append_scoped("capture-a", &[
        packet(1, 1, 14), packet(2, 2, 60), parse_ethernet(&[4; 14], 4, 1.0), packet(5, 5, 14),
    ]).unwrap();
    drop(archive);
    let mut bytes = std::fs::OpenOptions::new().write(true).open(archive_path.join("packets.bin")).unwrap();
    bytes.seek(SeekFrom::End(-1)).unwrap();
    bytes.write_all(&[255]).unwrap();
    drop(bytes);

    let mut center = AlertCenter::default();
    center.record(1, "IDS", "MEDIUM", "Recorded alert", "test");
    let mut first = center.items[0].clone();
    first.capture_id = Some("capture-a".into());
    let mut latest = first.clone();
    latest.packet_refs = vec![5, 4, 3, 2, 1, 2];
    let mut other = first.clone();
    other.capture_id = Some("capture-b".into());
    let log = directory.path().join("alerts.jsonl");
    let rows: Vec<_> = [first, latest, other].into_iter().map(|alert| {
        json!({ "schema_version": 1, "record_type": "alert", "session_id": "s", "alert": alert }).to_string()
    }).collect();
    std::fs::write(&log, rows.join("\n")).unwrap();
    let status = |filter: &[&str]| Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&archive_path).arg("--alert-status").arg(&log).args(["s", "1"])
        .args(filter).output().unwrap();
    let ambiguous = status(&[]);
    assert!(!ambiguous.status.success());
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("specify --capture-id"));
    let result = status(&["--capture-id", "capture-a"]);
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report, json!({
        "capture_id":"capture-a", "session_id":"s", "alert_id":1,
        "frames":[
            {"frame_number":1,"status":"complete"},
            {"frame_number":2,"status":"truncated"},
            {"frame_number":3,"status":"missing"},
            {"frame_number":4,"status":"length_unknown"},
            {"frame_number":5,"status":"unreadable"}
        ]
    }));

    let export = directory.path().join("export");
    let result = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&archive_path).arg("--alert-evidence").arg(&log).args(["s", "1"])
        .arg(&export).args(["--capture-id", "capture-b"]).output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let packets = packrat_tui::pcap_replay::read_pcap(&export.join("evidence.pcapng")).unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].bytes, [9; 14]);
}
