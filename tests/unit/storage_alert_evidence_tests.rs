use super::*;
use crate::analysis::alert_center::AlertCenter;
use crate::net::parser::parse_ethernet;
use crate::storage::alert_jsonl::MAX_ALERT_LINE;

fn snapshot(capture_id: Option<&str>) -> AlertItem {
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "HIGH", "Vertical port scan", "observed");
    let mut item = center.items.remove(0);
    item.capture_id = capture_id.map(str::to_owned);
    item
}

fn append_record(writer: &mut File, alert: &AlertItem) {
    let value = serde_json::json!({
        "schema_version": 1, "record_type": "alert", "session_id": "session", "alert": alert,
    });
    writeln!(writer, "{value}").unwrap();
}

#[test]
fn oversized_log_lines_do_not_hide_following_valid_records() {
    let temp = tempfile::tempdir().unwrap();
    let log = temp.path().join("alerts.jsonl");
    let mut writer = File::create(&log).unwrap();
    writer.write_all(&vec![b'*'; MAX_ALERT_LINE + 4]).unwrap();
    writer.write_all(b"\n").unwrap();
    append_record(&mut writer, &snapshot(Some("capture-a")));
    drop(writer);

    let item = latest_alert(&log, "session", 1, None).unwrap();
    assert_eq!(item.capture_id.as_deref(), Some("capture-a"));
    assert!(latest_alert(&log, "nonexistent-session", 1, None).is_err());
}

#[test]
fn an_unscoped_alert_is_rejected_and_unreadable_evidence_has_no_packet_capture() {
    let temp = tempfile::tempdir().unwrap();
    let log = temp.path().join("alerts.jsonl");
    let output = temp.path().join("evidence");
    let archive_path = temp.path().join("archive");
    let mut archive = PacketArchive::open(&archive_path).unwrap();
    let mut writer = File::create(&log).unwrap();
    append_record(&mut writer, &snapshot(None));
    let result = export_alert_evidence(&mut archive, &log, "session", 1, &output);
    assert!(result.err().unwrap().to_string().contains("no capture ID"));
    assert!(!output.exists());
    drop(writer);
    let mut writer = File::create(&log).unwrap();

    let first = parse_ethernet(&[1, 2, 3], 1, 1.0);
    let second = parse_ethernet(&[4, 5, 6], 2, 2.0);
    archive.append_scoped("capture-a", &[first, second]).unwrap();
    std::fs::write(archive_path.join("packets.bin"), [1, 2, 3, 7, 5, 6]).unwrap();
    let mut corrupted = snapshot(Some("capture-a"));
    corrupted.packet_refs.push(2);
    append_record(&mut writer, &corrupted);
    drop(writer);
    let result = export_alert_evidence(&mut archive, &log, "session", 1, &output).unwrap();
    assert_eq!((result.recovered_frames, result.missing_frames), (0, 2));
    assert_eq!((result.unreadable_frames, result.length_unknown_frames), (1, 1));
    assert!(!output.join(PCAP).exists());
    let verified = verify_alert_evidence(&output).unwrap();
    assert_eq!(verified.capture_sha256_verified, None);
    assert_eq!((verified.unreadable_frames, verified.length_unknown_frames), (1, 1));
    let checked = verify_archived_alert_evidence(&output, &archive_path, None).unwrap();
    assert_eq!(checked.archive_frames_verified, Some(0));
    assert_eq!(checked.capture_sha256_verified, None);
    assert_eq!(serde_json::to_value(checked).unwrap()["archive_omission_checks"], serde_json::json!([
        {"frame_number":1,"bundle_status":"length_unknown","archive_status_now":"length_unknown"},
        {"frame_number":2,"bundle_status":"unreadable","archive_status_now":"unreadable"},
    ]));
}

#[test]
fn alert_id_reused_across_capture_scopes_is_not_resolved_implicitly() {
    let temp = tempfile::tempdir().unwrap();
    let log = temp.path().join("alerts.jsonl");
    let mut writer = File::create(&log).unwrap();
    append_record(&mut writer, &snapshot(Some("capture-a")));
    append_record(&mut writer, &snapshot(Some("capture-b")));
    drop(writer);
    let error = latest_alert(&log, "session", 1, None).unwrap_err();
    assert!(error.to_string().contains("ambiguous across captures"));
    let item = latest_alert(&log, "session", 1, Some("capture-a")).unwrap();
    assert_eq!(item.capture_id.as_deref(), Some("capture-a"));
    assert!(latest_alert(&log, "session", 1, Some("missing-capture")).is_err());
}

#[test]
fn evidence_lookup_prefers_the_latest_snapshot_but_checks_older_scopes_for_ambiguity() {
    let temp = tempfile::tempdir().unwrap();
    let log = temp.path().join("alerts.jsonl");
    let older = temp.path().join("alerts.jsonl.1");
    let mut previous = File::create(&older).unwrap();
    let original = snapshot(Some("capture-a"));
    append_record(&mut previous, &original);
    append_record(&mut previous, &snapshot(Some("capture-b")));
    let mut current = File::create(&log).unwrap();
    append_record(&mut current, &original);
    let mut latest = original;
    latest.packet_refs.push(9);
    append_record(&mut current, &latest);
    current.write_all(b"{torn").unwrap();
    drop((current, previous));

    let previous = [older];
    let logs = || AlertLogs::new(&log, &previous).unwrap();
    let item = latest_alert_in_logs(logs(), "session", 1, Some("capture-a")).unwrap();
    assert_eq!(item.packet_refs, [1, 9]);
    assert_eq!(latest_alert_in_logs(logs(), "session", 1, Some("capture-b")).unwrap().packet_refs, [1]);
    assert!(latest_alert_in_logs(logs(), "session", 1, None).unwrap_err()
        .to_string().contains("ambiguous across captures"));
}

#[test]
fn evidence_verification_accepts_an_all_missing_manifest_without_claiming_a_digest() {
    let temp = tempfile::tempdir().unwrap();
    let log = temp.path().join("alerts.jsonl");
    let output = temp.path().join("evidence");
    let mut writer = File::create(&log).unwrap();
    append_record(&mut writer, &snapshot(Some("capture-a")));
    drop(writer);
    let mut archive = PacketArchive::open(&temp.path().join("archive")).unwrap();
    export_alert_evidence(&mut archive, &log, "session", 1, &output).unwrap();
    let report = verify_alert_evidence(&output).unwrap();
    assert_eq!(report.recovered_frames, 0);
    assert_eq!(report.missing_frames, 1);
    assert_eq!(report.capture_sha256_verified, None);
    File::create(output.join(PCAP)).unwrap();
    assert!(verify_alert_evidence(&output).err().unwrap().to_string().contains("does not reference"));
}

#[test]
fn unknown_wire_length_is_not_inferred_for_archived_alert_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let log = temp.path().join("alerts.jsonl");
    append_record(&mut File::create(&log).unwrap(), &snapshot(Some("capture-a")));
    let mut archive = PacketArchive::open(&temp.path().join("archive")).unwrap();
    archive.append_scoped("capture-a", &[parse_ethernet(&[1; 14], 1, 1.0)]).unwrap();

    let report = alert_evidence_availability(&mut archive, &log, "session", 1, Some("capture-a")).unwrap();
    assert!(matches!(report.frames[0].status, FrameStatus::LengthUnknown));
    let output = temp.path().join("evidence");
    let summary = export_alert_evidence(&mut archive, &log, "session", 1, &output).unwrap();
    assert_eq!((summary.recovered_frames, summary.missing_frames), (0, 1));
    assert!(!output.join(PCAP).exists());
    assert_eq!(archive.packet_for_capture("capture-a", 1).unwrap().unwrap().bytes, [1; 14]);
}
