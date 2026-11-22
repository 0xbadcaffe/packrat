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
    let previous = directory.path().join("alerts.jsonl.1");
    let row = |alert| {
        json!({ "schema_version": 1, "record_type": "alert", "session_id": "s", "alert": alert }).to_string()
    };
    std::fs::write(&previous, [row(first), row(other)].join("\n")).unwrap();
    std::fs::write(&log, row(latest)).unwrap();
    let status = |filter: &[&str]| Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&archive_path).arg("--alert-status").arg(&log).args(["s", "1"])
        .arg("--previous-log").arg(&previous)
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
    let missing = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&archive_path).arg("--alert-evidence").arg(&log).args(["s", "1"])
        .arg(&export).args(["--capture-id", "capture-b"]).output().unwrap();
    assert!(!missing.status.success());
    assert!(!export.exists());
    let result = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&archive_path).arg("--alert-evidence").arg(&log).args(["s", "1"])
        .arg(&export).args(["--capture-id", "capture-b"])
        .arg("--previous-log").arg(&previous).output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let packets = packrat_tui::pcap_replay::read_pcap(&export.join("evidence.pcapng")).unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].bytes, [9; 14]);

    let verify = || Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg("--verify-evidence").arg(&export).output().unwrap();
    let result = verify();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert_eq!(serde_json::from_slice::<Value>(&result.stdout).unwrap(), json!({
        "session_id":"s", "capture_id":"capture-b", "alert_id":1, "recovered_frames":1,
        "missing_frames":0, "capture_sha256_verified":true
    }));

    let manifest = export.join("manifest.json");
    let original = std::fs::read(&manifest).unwrap();
    let mut altered: Value = serde_json::from_slice(&original).unwrap();
    altered["capture"]["source_frame_numbers"] = json!([3]);
    std::fs::write(&manifest, serde_json::to_vec(&altered).unwrap()).unwrap();
    let result = verify();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("mapping does not match alert references"));
    std::fs::write(&manifest, original).unwrap();

    let capture = export.join("evidence.pcapng");
    let mut bytes = std::fs::read(&capture).unwrap();
    let frame = bytes.windows(14).position(|slice| slice == [9; 14]).unwrap();
    bytes[frame] = 8;
    std::fs::write(&capture, bytes).unwrap();
    let result = verify();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("SHA-256 mismatch"));
}
