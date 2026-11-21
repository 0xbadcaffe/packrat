use super::*;
use crate::analysis::alert_center::AlertCenter;
use crate::net::parser::parse_ethernet;

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

    let item = latest_alert(&log, "session", 1).unwrap();
    assert_eq!(item.capture_id.as_deref(), Some("capture-a"));
    assert!(latest_alert(&log, "nonexistent-session", 1).is_err());
}

#[test]
fn ambiguous_or_corrupted_evidence_does_not_leave_a_bundle() {
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

    let first = parse_ethernet(&[1, 2, 3], 1, 1.0);
    let second = parse_ethernet(&[4, 5, 6], 2, 2.0);
    archive.append_scoped("capture-a", &[first, second]).unwrap();
    std::fs::write(archive_path.join("packets.bin"), [1, 2, 3, 7, 5, 6]).unwrap();
    let mut corrupted = snapshot(Some("capture-a"));
    corrupted.packet_refs.push(2);
    append_record(&mut writer, &corrupted);
    drop(writer);
    let result = export_alert_evidence(&mut archive, &log, "session", 1, &output);
    assert!(result.err().unwrap().to_string().contains("integrity"));
    assert!(!output.exists());
}
