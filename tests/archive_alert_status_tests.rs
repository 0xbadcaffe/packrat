use std::io::{Seek, SeekFrom, Write};
use std::process::Command;

use packrat_tui::analysis::alert_center::AlertCenter;
use packrat_tui::net::packet::CaptureMetadata;
use packrat_tui::net::parser::parse_ethernet;
use packrat_tui::storage::packet_archive::PacketArchive;
use serde_json::{Value, json};

#[cfg(unix)]
#[test]
fn archive_reader_rejects_named_pipes_and_symlinks_without_waiting() {
    use std::{
        ffi::CString,
        os::unix::{ffi::OsStrExt, fs::symlink},
        path::Path,
        process::Stdio,
        time::{Duration, Instant},
    };

    let scratch = tempfile::tempdir().unwrap();
    let archive = scratch.path().join("archive");
    drop(PacketArchive::open(&archive).unwrap());
    let run = |path: &Path| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
            .arg(path).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().ok();
                child.wait().unwrap();
                panic!("Archive reader blocked on {}", path.display());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.wait_with_output().unwrap()
    };
    assert!(run(&archive).status.success());
    let reject = |path: &Path, name: &str| {
        let output = run(path);
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("not a real directory or regular file") && error.contains(name), "{error}");
    };
    let file = archive.join("packets.bin");
    let backup = scratch.path().join("original.bin");
    std::fs::rename(&file, &backup).unwrap();
    let fifo = CString::new(file.as_os_str().as_bytes()).unwrap();
    // SAFETY: fifo is a valid, null-terminated path in the fixture directory.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    reject(&archive, "packets.bin");
    std::fs::remove_file(&file).unwrap();
    symlink(&backup, &file).unwrap();
    reject(&archive, "packets.bin");
    std::fs::remove_file(&file).unwrap();
    std::fs::rename(&backup, &file).unwrap();
    let sidecar = archive.join("index.sqlite-wal");
    let sidecar_backup = scratch.path().join("original.wal");
    if sidecar.exists() {
        std::fs::rename(&sidecar, &sidecar_backup).unwrap();
    }
    symlink(&file, &sidecar).unwrap();
    reject(&archive, "index.sqlite-wal");
    std::fs::remove_file(&sidecar).unwrap();
    if sidecar_backup.exists() {
        std::fs::rename(&sidecar_backup, &sidecar).unwrap();
    }
    let alias = scratch.path().join("alias");
    symlink(&archive, &alias).unwrap();
    reject(&alias, "alias");
    assert!(run(&archive).status.success());
}

#[test]
fn project_alert_status_checks_only_unique_scoped_pins_against_the_log() {
    use packrat_tui::model::project::{ProjectSaveMode, ProjectState};
    use packrat_tui::storage::project_store;

    let root = tempfile::tempdir().unwrap();
    let project_path = root.path().join("case.json");
    let log = root.path().join("alerts.jsonl");
    let previous = root.path().join("alerts.jsonl.1");
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "MEDIUM", "Recorded alert", "test");
    let mut alert = center.items[0].clone();
    alert.capture_id = Some("capture-a".into());
    alert.packet_refs = vec![1, 2, 3, 4, 5, 6, 7];
    std::fs::write(&log, "").unwrap();
    std::fs::write(&previous, json!({
        "schema_version":1, "record_type":"alert", "session_id":"s", "alert":alert
    }).to_string()).unwrap();

    let packet = |no, captured_length, wire_length| {
        let mut packet = parse_ethernet(&[no as u8; 14], no, 1.0);
        packet.capture = Some(CaptureMetadata {
            timestamp: None, captured_length, wire_length, link_type: 1,
            interface_id: 0, section_id: 0, interface_name: None, comments: Vec::new(),
        });
        packet
    };
    let mut project = ProjectState::new("case", ProjectSaveMode::Lightweight);
    project.pinned_packets = vec![
        packet(1, 14, 14), packet(2, 14, 60), packet(3, 14, 14), packet(4, 14, 14),
        packet(4, 14, 14), packet(5, 13, 14), parse_ethernet(&[0; 14], 6, 1.0),
    ];
    project.pinned_packet_scopes = [1, 2, 4, 5, 6].map(|no| (no, "capture-a".into())).into();
    project.pinned_packet_scopes.insert(3, "capture-b".into());
    project.embedded_packets.push(packet(7, 14, 14));
    project_store::create(&project, &project_path).unwrap();
    let before = std::fs::read(&project_path).unwrap();

    let status = |capture| Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg("--project-alert-status").arg(&project_path).arg(&log)
        .args(["s", capture, "1", "--previous-log"]).arg(&previous).output().unwrap();
    assert!(!status("capture-b").status.success());
    let result = status("capture-a");
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["capture_id"], "capture-a");
    assert_eq!(report["evidence_frame_set_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(report["frames"], json!([
        {"frame_number":1,"status":"complete"},
        {"frame_number":2,"status":"truncated"},
        {"frame_number":3,"status":"missing"},
        {"frame_number":4,"status":"unreadable"},
        {"frame_number":5,"status":"unreadable"},
        {"frame_number":6,"status":"length_unknown"},
        {"frame_number":7,"status":"missing"},
    ]));

    let output = root.path().join("evidence");
    let export = |capture| Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg("--project-alert-evidence").arg(&project_path).arg(&log)
        .args(["s", capture, "1"]).arg(&output)
        .args(["--previous-log"]).arg(&previous).output().unwrap();
    assert!(!export("capture-b").status.success());
    assert!(!output.exists());
    let result = export("capture-a");
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert_eq!(serde_json::from_slice::<Value>(&result.stdout).unwrap(),
        json!({"recovered_frames":2,"missing_frames":5,"unreadable_frames":2,"length_unknown_frames":1}));

    let manifest_path = output.join("manifest.json");
    let manifest = std::fs::read(&manifest_path).unwrap();
    let view: Value = serde_json::from_slice(&manifest).unwrap();
    assert_eq!(view["capture"]["source_frame_numbers"], json!([1, 2]));
    assert_eq!(view["missing_frame_numbers"], json!([3, 4, 5, 6, 7]));
    assert_eq!(view["unreadable_frame_numbers"], json!([4, 5]));
    assert_eq!(view["length_unknown_frame_numbers"], json!([6]));
    let mut payloads = Vec::new();
    packrat_tui::pcap_replay::stream_pcap(&output.join("evidence.pcapng"), |packet| {
        payloads.push((packet.capture.unwrap().wire_length, packet.bytes));
        Ok(())
    }).unwrap();
    assert_eq!(payloads, [(14, vec![1; 14]), (60, vec![2; 14])]);
    let verified = packrat_tui::storage::alert_evidence::verify_alert_evidence(&output).unwrap();
    assert_eq!(verified.capture_sha256_verified, Some(true));
    assert!(!export("capture-a").status.success());
    assert_eq!(std::fs::read(&manifest_path).unwrap(), manifest);
    let mut updated = view["alert"].clone();
    updated["detail"] = json!("newer observation");
    updated["hit_count"] = json!(2);
    std::fs::write(&log, json!({
        "schema_version":1, "record_type":"alert", "session_id":"s", "alert":updated
    }).to_string()).unwrap();
    let verify_logged = |include_previous| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_packrat-archive"));
        command.arg("--verify-evidence").arg(&output).arg("--alert-log").arg(&log);
        if include_previous {
            command.arg("--previous-log").arg(&previous);
        }
        command.output().unwrap()
    };
    assert!(!verify_logged(false).status.success());
    let report = verify_logged(true);
    assert!(report.status.success(), "{}", String::from_utf8_lossy(&report.stderr));
    let report: Value = serde_json::from_slice(&report.stdout).unwrap();
    assert_eq!(report["alert_snapshot_matches_log"], true);
    assert_eq!(report["capture_sha256_verified"], true);

    let mut changed = view;
    changed["alert"]["detail"] = json!("unlogged detail");
    std::fs::write(&manifest_path, changed.to_string()).unwrap();
    assert!(packrat_tui::storage::alert_evidence::verify_alert_evidence(&output).is_ok());
    let mismatch = verify_logged(true);
    assert!(!mismatch.status.success());
    assert!(String::from_utf8_lossy(&mismatch.stderr).contains("No matching evidence alert snapshot"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&output).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(output.join("evidence.pcapng")).unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(std::fs::read(&project_path).unwrap(), before);
}

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
    let history = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg("--alerts").arg(&log).args(["--session", "s", "--capture-id", "capture-a"])
        .output().unwrap();
    assert!(history.status.success());
    let history: Value = serde_json::from_slice(&history.stdout).unwrap();
    let fingerprint = history[0]["evidence_frame_set_sha256"].as_str().unwrap();
    assert_eq!(fingerprint.len(), 64);
    assert_eq!(report, json!({
        "capture_id":"capture-a", "session_id":"s", "alert_id":1,
        "evidence_frame_set_sha256":fingerprint,
        "frames":[
            {"frame_number":1,"status":"complete"},
            {"frame_number":2,"status":"truncated"},
            {"frame_number":3,"status":"missing"},
            {"frame_number":4,"status":"length_unknown"},
            {"frame_number":5,"status":"unreadable"}
        ]
    }));
    let recovered = directory.path().join("with-unreadable");
    let result = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&archive_path).arg("--alert-evidence").arg(&log).args(["s", "1"])
        .arg(&recovered).args(["--capture-id", "capture-a"]).output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert_eq!(serde_json::from_slice::<Value>(&result.stdout).unwrap(), json!({
        "recovered_frames":2,"missing_frames":3,"unreadable_frames":1,"length_unknown_frames":1
    }));
    let manifest_path = recovered.join("manifest.json");
    let manifest: Value = serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    assert_eq!(manifest["capture"]["source_frame_numbers"], json!([1, 2]));
    assert_eq!(manifest["missing_frame_numbers"], json!([3, 4, 5]));
    assert_eq!(manifest["unreadable_frame_numbers"], json!([5]));
    assert_eq!(manifest["length_unknown_frame_numbers"], json!([4]));
    let verify = || packrat_tui::storage::alert_evidence::verify_alert_evidence(&recovered);
    let report = verify().unwrap();
    let verified = serde_json::to_value(report).unwrap();
    assert_eq!(verified["unreadable_frames"], 1);
    assert_eq!(verified["length_unknown_frames"], 1);
    let archived = packrat_tui::storage::alert_evidence::verify_archived_alert_evidence(
        &recovered, &archive_path, None,
    ).unwrap();
    assert_eq!(archived.archive_frames_verified, Some(2));
    for (key, frames) in [("unreadable_frame_numbers", json!([1])),
        ("unreadable_frame_numbers", json!([4, 5])), ("length_unknown_frame_numbers", json!([4, 4]))] {
        let mut invalid = manifest.clone();
        invalid[key] = frames;
        std::fs::write(&manifest_path, invalid.to_string()).unwrap();
        assert!(verify().is_err(), "{key}");
    }
    let mut updated = serde_json::from_slice::<Value>(&std::fs::read(&log).unwrap()).unwrap();
    updated["alert"]["packet_refs"] = json!([6, 4, 3, 2, 1, 2]);
    let mut writer = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
    writeln!(writer, "\n{updated}").unwrap();
    drop(writer);
    let result = status(&["--capture-id", "capture-a"]);
    assert!(result.status.success());
    let changed: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_ne!(changed["evidence_frame_set_sha256"], fingerprint);
    assert_eq!(changed["frames"].as_array().unwrap().len(), 5);

    let partial = directory.path().join("partial");
    let result = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&archive_path).arg("--alert-evidence").arg(&log).args(["s", "1"])
        .arg(&partial).args(["--capture-id", "capture-a"]).output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let report = packrat_tui::storage::alert_evidence::verify_alert_evidence(&partial).unwrap();
    assert_eq!((report.recovered_frames, report.missing_frames), (2, 3));
    let manifest: Value = serde_json::from_slice(&std::fs::read(partial.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["missing_frame_numbers"], json!([3, 4, 6]));
    let packets = packrat_tui::pcap_replay::read_pcap(&partial.join("evidence.pcapng")).unwrap();
    assert_eq!(packets[1].capture.as_ref().unwrap().wire_length, 60);

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
    let verify_archive = || Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg("--verify-evidence").arg(&export).arg("--archive").arg(&archive_path)
        .arg("--alert-log").arg(&log).arg("--previous-log").arg(&previous).output().unwrap();
    let checked = verify_archive();
    assert!(checked.status.success(), "{}", String::from_utf8_lossy(&checked.stderr));
    assert_eq!(serde_json::from_slice::<Value>(&checked.stdout).unwrap(), json!({
        "session_id":"s", "capture_id":"capture-b", "alert_id":1, "recovered_frames":1,
        "missing_frames":0, "capture_sha256_verified":true, "alert_snapshot_matches_log":true,
        "archive_frames_verified":1
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
    std::fs::write(&capture, &bytes).unwrap();
    let result = verify();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("SHA-256 mismatch"));
    // A replaced packet and rewritten manifest digest pass local checksum validation.
    use sha2::{Digest, Sha256};
    let mut forged: Value = serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    forged["capture"]["sha256"] = json!(format!("{:x}", Sha256::digest(&bytes)));
    std::fs::write(&manifest, forged.to_string()).unwrap();
    assert!(verify().status.success());
    let rejected = verify_archive();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("does not match the archived frames"));
}
