use packrat_tui::pcap_replay::read_pcap;

fn pcap(frame: &[u8], link_type: u32, nanos: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(if nanos {
        &[0x4d, 0x3c, 0xb2, 0xa1]
    } else {
        &[0xd4, 0xc3, 0xb2, 0xa1]
    });
    bytes.extend_from_slice(&2_u16.to_le_bytes());
    bytes.extend_from_slice(&4_u16.to_le_bytes());
    bytes.extend_from_slice(&0_i32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&65_535_u32.to_le_bytes());
    bytes.extend_from_slice(&link_type.to_le_bytes());
    bytes.extend_from_slice(&7_u32.to_le_bytes());
    bytes.extend_from_slice(&500_000_u32.to_le_bytes());
    bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    bytes.extend_from_slice(frame);
    bytes
}

fn ipv6_tcp_frame() -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + 40 + 20];
    frame[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
    frame[14] = 0x60;
    frame[18..20].copy_from_slice(&20_u16.to_be_bytes());
    frame[20] = 6;
    frame[22..38].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    frame[38..54].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    frame[54..56].copy_from_slice(&40_000_u16.to_be_bytes());
    frame[56..58].copy_from_slice(&443_u16.to_be_bytes());
    frame[66] = 0x50;
    frame[67] = 0x02;
    frame
}

fn write_temp(contents: &[u8], label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("packrat-{label}-{}.pcap", std::process::id()));
    std::fs::write(&path, contents).unwrap();
    path
}

#[test]
fn imported_pcap_uses_the_full_ethernet_parser_for_ipv6() {
    let path = write_temp(&pcap(&ipv6_tcp_frame(), 1, true), "ipv6");
    let packets = read_pcap(&path).unwrap();
    let _ = std::fs::remove_file(path);
    assert_eq!(packets[0].protocol, "HTTPS");
    assert_eq!(packets[0].src, "2001:0db8:0000:0000:0000:0000:0000:0001");
    assert_eq!(packets[0].dst_port, Some(443));
    assert!((packets[0].timestamp - 7.0005).abs() < 1e-12);
}

#[test]
fn imported_pcap_rejects_unsupported_links_and_truncation() {
    let frame = ipv6_tcp_frame();
    let unsupported = write_temp(&pcap(&frame, 101, false), "raw-link");
    assert!(read_pcap(&unsupported).unwrap_err().contains("link type"));
    let _ = std::fs::remove_file(unsupported);

    let mut truncated = pcap(&frame, 1, false);
    truncated.pop();
    let truncated = write_temp(&truncated, "truncated");
    assert!(read_pcap(&truncated).unwrap_err().contains("Truncated"));
    let _ = std::fs::remove_file(truncated);
}

#[test]
fn streaming_reader_stops_on_consumer_error() {
    let mut bytes = pcap(&ipv6_tcp_frame(), 1, false);
    let record = bytes[24..].to_vec();
    bytes.extend_from_slice(&record);
    let path = write_temp(&bytes, "consumer-error");
    let mut seen = 0;
    let result = packrat_tui::pcap_replay::stream_pcap(&path, |_| {
        seen += 1;
        Err("archive full".into())
    });
    assert_eq!(seen, 1);
    assert_eq!(result.unwrap_err(), "archive full");
    std::fs::remove_file(path).unwrap();
}

#[test]
fn streaming_reader_rejects_invalid_timestamps_and_wire_lengths() {
    for (offset, value, label) in [(28, 1_000_000u32, "fraction"), (36, 1u32, "wire-length")] {
        let mut bytes = pcap(&ipv6_tcp_frame(), 1, false);
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        let path = write_temp(&bytes, label);
        assert!(read_pcap(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn archive_cli_imports_and_recovers_captured_packets() {
    let path = write_temp(&pcap(&ipv6_tcp_frame(), 1, true), "archive-cli");
    let archive = std::env::temp_dir().join(format!("packrat-cli-{}-{}", std::process::id(), rand::random::<u64>()));
    let binary = env!("CARGO_BIN_EXE_packrat-archive");
    let result = std::process::Command::new(binary).arg(&archive).arg("--import").arg(&path).output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert!(String::from_utf8_lossy(&result.stdout).contains("Imported 1 packets"));
    let result = std::process::Command::new(binary).arg(&archive).arg("1").output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let packet: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(packet["protocol"], "HTTPS");
    assert_eq!(packet["bytes"].as_array().unwrap().len(), ipv6_tcp_frame().len());
    let result = std::process::Command::new(binary).arg(&archive).arg("--host").arg("2001:0db8:0000:0000:0000:0000:0000:0001").output().unwrap();
    assert!(result.status.success());
    assert_eq!(serde_json::from_slice::<Vec<i64>>(&result.stdout).unwrap(), vec![1]);
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir_all(archive).unwrap();
}

#[test]
fn archive_cli_recovers_a_frame_only_from_the_requested_capture() {
    use packrat_tui::storage::packet_archive::PacketArchive;

    let directory = tempfile::tempdir().unwrap();
    let packet = packrat_tui::net::parser::parse_ethernet(&ipv6_tcp_frame(), 17, 1.0);
    let archive_path = directory.path().join("archive");
    let mut archive = PacketArchive::open(&archive_path).unwrap();
    archive.append_scoped("capture-a", &[packet.clone()]).unwrap();
    drop(archive);

    let lookup = |capture: &str| {
        std::process::Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
            .arg(&archive_path)
            .args(["--capture-frame", capture, "17"])
            .output()
            .unwrap()
    };
    let found = lookup("capture-a");
    assert!(found.status.success());
    let recovered: packrat_tui::net::packet::Packet = serde_json::from_slice(&found.stdout).unwrap();
    assert_eq!(recovered.bytes, packet.bytes);
    let missing = lookup("capture-b");
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("Frame not found"));
}

#[test]
fn archive_cli_exports_latest_scoped_alert_with_provenance_and_missing_frames() {
    use packrat_tui::analysis::alert_center::AlertCenter;
    use packrat_tui::storage::packet_archive::PacketArchive;
    use sha2::{Digest, Sha256};

    let directory = tempfile::tempdir().unwrap();
    let archive_path = directory.path().join("archive");
    let mut archive = PacketArchive::open(&archive_path).unwrap();
    let frame = ipv6_tcp_frame();
    let mut other_bytes = frame.clone();
    other_bytes[0] ^= 1;
    let source = directory.path().join("source.pcap");
    std::fs::write(&source, pcap(&frame, 1, false)).unwrap();
    let mut exact = read_pcap(&source).unwrap().remove(0);
    exact.no = 7;
    let other = packrat_tui::net::parser::parse_ethernet(&other_bytes, 7, 1.0);
    let missing_in_a = packrat_tui::net::parser::parse_ethernet(&other_bytes, 8, 2.0);
    archive.append_scoped("capture-a", &[exact]).unwrap();
    archive.append_scoped("capture-b", &[other, missing_in_a]).unwrap();
    drop(archive);

    let mut alerts = AlertCenter::default();
    alerts.record(7, "IDS", "HIGH", "Horizontal host scan", "first snapshot");
    let mut first = alerts.items[0].clone();
    first.capture_id = Some("capture-a".into());
    let mut latest = first.clone();
    latest.packet_no = 8;
    latest.last_packet = 8;
    latest.packet_refs = vec![8, 7, 7];
    latest.hit_count = 2;
    let mut wrong_session = latest.clone();
    wrong_session.capture_id = Some("capture-b".into());
    let record = |session, alert| serde_json::json!({
        "schema_version": 1, "record_type": "alert", "session_id":session, "alert": alert
    });
    let log = directory.path().join("alerts.jsonl");
    std::fs::write(
        &log,
        format!("{}\nnot-json\n{}\n{}\n", record("session-a", first), record("session-a", latest), record("session-b", wrong_session)),
    ).unwrap();

    let output = directory.path().join("evidence");
    let export = || std::process::Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&archive_path)
        .arg("--alert-evidence")
        .arg(&log)
        .args(["session-a", "1"])
        .arg(&output)
        .output().unwrap();
    let result = export();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let summary: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(summary, serde_json::json!({"recovered_frames":1,"missing_frames":1}));

    let path = output.join("evidence.pcapng");
    let packets = read_pcap(&path).unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].bytes, frame);
    let digest = format!("{:x}", Sha256::digest(std::fs::read(&path).unwrap()));
    let manifest_bytes = std::fs::read(output.join("manifest.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest["alert"]["provenance"]["rule_id"], "scan.horizontal");
    assert_eq!(manifest["alert"]["provenance"]["revision"], 15);
    assert_eq!(manifest["alert"]["hit_count"], 2);
    assert_eq!(manifest["capture"]["source_frame_numbers"], serde_json::json!([7]));
    assert_eq!(manifest["missing_frame_numbers"], serde_json::json!([8]));
    assert_eq!(manifest["capture"]["sha256"], digest);
    assert!(!export().status.success());
    assert_eq!(std::fs::read(output.join("manifest.json")).unwrap(), manifest_bytes);
}
