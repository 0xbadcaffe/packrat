use super::*;
use crate::analysis::alert_center::{AlertDisposition, AlertItem};

fn alert(hit_count: u64, packet_no: u64) -> AlertItem {
    AlertItem {
        id: 1,
        packet_no,
        source: "test-rule".into(),
        severity: "HIGH".into(),
        title: "Suspicious request".into(),
        detail: format!("Observed packet {packet_no}"),
        disposition: AlertDisposition::New,
        priority: 80,
        recommendation: None,
        correlation_key: "flow-1".into(),
        hit_count,
        first_packet: 1,
        last_packet: packet_no,
        first_seen: 1.0,
        last_seen: packet_no as f64,
        packet_refs: if packet_no == 1 {
            vec![1]
        } else {
            vec![1, packet_no]
        },
        capture_id: None,
        provenance: None,
        flow: None,
    }
}

#[test]
fn enabling_saving_backfills_alerts_without_duplicate_snapshots() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("alerts.jsonl");

    let mut writer = AlertJsonlWriter::open(path.clone(), "session-a").unwrap();
    writer.append_alerts(&[alert(1, 1)]).unwrap();
    drop(writer);

    let mut writer = AlertJsonlWriter::open(path.clone(), "session-a").unwrap();
    writer
        .backfill(&[alert(1, 1), alert(2, 2)], &[alert(2, 2)])
        .unwrap();
    drop(writer);

    let records: Vec<serde_json::Value> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["alert"]["hit_count"], 1);
    assert_eq!(records[1]["alert"]["hit_count"], 2);
}

#[test]
fn identical_alerts_from_a_new_session_are_kept() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("alerts.jsonl");

    AlertJsonlWriter::open(path.clone(), "session-a")
        .unwrap()
        .append_alerts(&[alert(1, 1)])
        .unwrap();
    AlertJsonlWriter::open(path.clone(), "session-b")
        .unwrap()
        .append_alerts(&[alert(1, 1)])
        .unwrap();

    assert_eq!(std::fs::read_to_string(path).unwrap().lines().count(), 2);
}

#[test]
fn saved_alert_qualifies_frame_numbers_with_the_capture_id() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("alerts.jsonl");
    let mut item = alert(2, 4);
    item.capture_id = Some("capture-b".into());
    AlertJsonlWriter::open(path.clone(), "process-a")
        .unwrap()
        .append_alerts(&[item])
        .unwrap();

    let record: ExistingAlertRecord =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(record.session_id, "process-a");
    assert_eq!(record.alert.capture_id.as_deref(), Some("capture-b"));
    assert_eq!(record.alert.packet_refs, [1, 4]);
}

fn read_log(path: &std::path::Path) -> Vec<ExistingAlertRecord> {
    std::fs::read_to_string(path).unwrap().lines()
        .filter_map(|line| ExistingAlertRecord::decode(line.as_bytes()))
        .collect()
}

fn write_private_log(path: &std::path::Path, contents: &[u8]) {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).unwrap().write_all(contents).unwrap();
}

#[test]
fn disposition_can_return_to_a_previously_logged_state() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("alerts.jsonl");
    let original = alert(1, 1);
    let mut reviewed = original.clone();
    reviewed.disposition = AlertDisposition::Reviewing;
    let mut writer = AlertJsonlWriter::open(path.clone(), "session-a").unwrap();
    writer.append_alerts(&[original.clone(), reviewed]).unwrap();
    drop(writer);

    let mut writer = AlertJsonlWriter::open(path.clone(), "session-a").unwrap();
    writer.append_alerts(&[original.clone(), original]).unwrap();
    let records = read_log(&path);
    assert_eq!(records.iter().map(|row| row.alert.disposition).collect::<Vec<_>>(), [
        AlertDisposition::New, AlertDisposition::Reviewing, AlertDisposition::New
    ]);
}

#[test]
fn reopening_deduplicates_valid_records_even_when_their_json_formatting_differs() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("alerts.jsonl");
    let original = alert(1, 1);
    let record = serde_json::json!({
        "schema_version": 1, "record_type": "alert", "session_id": "session-a", "alert": original,
    });
    write_private_log(&path, format!("  {record}  \r\n").as_bytes());
    let mut writer = AlertJsonlWriter::open(path.clone(), "session-a").unwrap();
    writer.append_alerts(&[original, alert(2, 2)]).unwrap();
    let records = read_log(&path);
    assert_eq!(records.iter().map(|row| row.alert.hit_count).collect::<Vec<_>>(), [1, 2]);
}

#[test]
fn backfill_cannot_replace_current_alert_with_stale_pending_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("alerts.jsonl");
    let mut writer = AlertJsonlWriter::open(path.clone(), "session-a").unwrap();
    writer.append_alerts(&[alert(1, 1)]).unwrap();
    let mut pending_only = alert(2, 4);
    pending_only.id = 2;
    writer.backfill(&[alert(3, 3)], &[alert(2, 2), pending_only]).unwrap();
    let records = read_log(&path);
    assert_eq!(records.iter().map(|row| (row.alert.id, row.alert.hit_count)).collect::<Vec<_>>(), [
        (1, 1), (1, 3), (2, 2)
    ]);
}

#[test]
fn saved_snapshot_index_stays_bounded_when_reopening_long_logs() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("alerts.jsonl");
    let mut writer = AlertJsonlWriter::open(path.clone(), "session-a").unwrap();
    let snapshots: Vec<_> = (1..=MAX_SAVED_ALERTS as u64 + 1).map(|id| {
        let mut item = alert(1, id);
        item.id = id;
        item
    }).collect();
    writer.append_alerts(&snapshots).unwrap();
    assert_eq!(writer.latest_snapshots.len(), MAX_SAVED_ALERTS);
    drop(writer);
    let writer = AlertJsonlWriter::open(path, "session-a").unwrap();
    assert_eq!(writer.latest_snapshots.len(), MAX_SAVED_ALERTS);
    assert!(!writer.latest_snapshots.contains_key(&(1, None)));
    assert!(writer.latest_snapshots.contains_key(&(MAX_SAVED_ALERTS as u64 + 1, None)));
}

#[test]
fn reopening_after_a_torn_line_does_not_lose_the_next_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("alerts.jsonl");
    write_private_log(&path, b"{\"alert\":");
    let mut writer = AlertJsonlWriter::open(path.clone(), "session-a").unwrap();
    writer.append_alerts(&[alert(1, 1)]).unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.starts_with("{\"alert\":\n"));
    assert_eq!(read_log(&path).len(), 1);
}

#[test]
fn failed_record_write_does_not_suppress_the_retry() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("alerts.jsonl");
    let original = alert(1, 1);
    let updated = alert(2, 2);
    let mut writer = AlertJsonlWriter::open(path.clone(), "session-a").unwrap();
    writer.append_alerts(std::slice::from_ref(&original)).unwrap();
    let previous_digest = writer.latest_snapshots[&snapshot_key(&original)];

    let writable = std::mem::replace(&mut writer.writer, File::open(&path).unwrap());
    assert!(writer.append_alerts(std::slice::from_ref(&updated)).is_err());
    assert_eq!(read_log(&path).len(), 1);
    assert_eq!(
        writer.latest_snapshots.get(&snapshot_key(&updated)),
        Some(&previous_digest),
    );
    writer.writer = writable;
    writer.append_alerts(&[updated.clone(), updated]).unwrap();
    let records = read_log(&path);
    assert_eq!(records.len(), 2);
    assert_eq!(records[1].alert.hit_count, 2);
    assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
}

#[cfg(unix)]
#[test]
fn saved_alerts_follow_renamed_logs_without_replaying_old_snapshots() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("alerts.jsonl");
    let previous = directory.path().join("alerts.jsonl.1");
    let mut writer = AlertJsonlWriter::open(path.clone(), "session-a").unwrap();
    let first = alert(1, 1);
    writer.append_alerts(std::slice::from_ref(&first)).unwrap();
    std::fs::rename(&path, &previous).unwrap();

    writer.append_alerts(&[]).unwrap();
    assert!(!path.exists());
    writer.append_alerts(&[first, alert(2, 2)]).unwrap();
    let old = read_log(&previous);
    let current = read_log(&path);
    assert_eq!(old.len(), 1);
    assert_eq!(old[0].alert.hit_count, 1);
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].session_id, "session-a");
    assert_eq!(current[0].alert.packet_refs, [1, 2]);
    assert_eq!(current[0].alert.hit_count, 2);
}

#[cfg(unix)]
#[test]
fn rotated_replacement_with_a_torn_record_preserves_the_next_alert() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("alerts.jsonl");
    let previous = directory.path().join("alerts.jsonl.1");
    let mut writer = AlertJsonlWriter::open(path.clone(), "session-a").unwrap();
    writer.append_alerts(&[alert(1, 1)]).unwrap();
    std::fs::rename(&path, &previous).unwrap();
    write_private_log(&path, b"{\"alert\":");

    writer.append_alerts(&[alert(2, 2), alert(3, 3)]).unwrap();
    assert!(std::fs::read_to_string(&path).unwrap().starts_with("{\"alert\":\n"));
    assert_eq!(read_log(&previous).len(), 1);
    assert_eq!(
        read_log(&path).iter().map(|record| record.alert.hit_count).collect::<Vec<_>>(),
        [2, 3],
    );
}

#[cfg(unix)]
#[test]
fn saved_alert_log_rejects_broad_permissions_without_rewriting_contents() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("alerts.jsonl");
    write_private_log(&path, b"old record\n");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = AlertJsonlWriter::open(path.clone(), "session-a").err().unwrap();
    assert!(error.contains("chmod 600"), "{error}");
    assert_eq!(std::fs::read(&path).unwrap(), b"old record\n");
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o644);

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut writer = AlertJsonlWriter::open(path.clone(), "session-a").unwrap();
    writer.append_alerts(&[alert(1, 1)]).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(writer.append_alerts(&[alert(2, 2)]).is_err());
    assert_eq!(read_log(&path)[0].alert.hit_count, 1);
}

#[cfg(unix)]
#[test]
fn saved_alert_log_rejects_redirects_and_nonregular_file() {
    use std::os::unix::{fs::symlink, net::UnixListener};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("alerts.jsonl");
    let other = directory.path().join("other.jsonl");
    write_private_log(&other, b"untouched\n");

    let mut writer = AlertJsonlWriter::open(path.clone(), "session-a").unwrap();
    writer.append_alerts(&[alert(1, 1)]).unwrap();
    let previous = directory.path().join("alerts.jsonl.1");
    std::fs::rename(&path, &previous).unwrap();

    symlink(&other, &path).unwrap();
    assert!(AlertJsonlWriter::open(path.clone(), "session-a").is_err());
    assert!(writer.append_alerts(&[alert(2, 2)]).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::hard_link(&other, &path).unwrap();
    assert!(AlertJsonlWriter::open(path.clone(), "session-a").is_err());
    assert!(writer.append_alerts(&[alert(2, 2)]).is_err());
    std::fs::remove_file(&path).unwrap();
    let _listener = UnixListener::bind(&path).unwrap();
    assert!(AlertJsonlWriter::open(path, "session-a").is_err());
    assert_eq!(std::fs::read(&other).unwrap(), b"untouched\n");
    assert_eq!(read_log(&previous).len(), 1);
}
