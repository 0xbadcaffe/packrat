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
