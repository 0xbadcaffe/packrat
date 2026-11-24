use super::*;
use crate::analysis::alert_center::AlertCenter;
use crate::storage::alert_jsonl::AlertJsonlWriter;

fn alert(id: u64, scope: &str) -> AlertItem {
    let mut center = AlertCenter::default();
    center.record(id, "test", "HIGH", "Recovery", "example");
    let mut alert = center.items.remove(0);
    alert.id = id;
    alert.capture_id = Some(scope.into());
    alert
}

#[test]
fn keeps_latest_snapshots_by_alert_and_capture_within_the_entry_limit() {
    let mut backlog = AlertWriteBacklog::default();
    backlog.extend((1..=MAX_SNAPSHOTS as u64).map(|id| alert(id, "capture-a")).collect());
    let mut updated = alert(2, "capture-a");
    updated.hit_count = 9;
    backlog.extend(vec![updated, alert(2, "capture-b")]);
    assert_eq!(backlog.iter().count(), MAX_SNAPSHOTS);
    assert_eq!(backlog.dropped, 1);
    let mut kept = backlog.iter();
    let first = kept.next().unwrap();
    assert_eq!((first.id, first.hit_count), (2, 9));
    assert_eq!(kept.next().unwrap().capture_id.as_deref(), Some("capture-b"));
}

#[test]
fn enforces_the_heap_budget_and_preserves_the_drop_counter_after_clear() {
    let mut backlog = AlertWriteBacklog::default();
    let mut oversized = alert(3, "scope");
    oversized.correlation_key = String::with_capacity(MAX_BYTES + 1);
    oversized.correlation_key.push('x');
    let mut first = alert(1, "scope");
    first.correlation_key = "x".repeat(MAX_BYTES / 2 + 1);
    let mut second = first.clone();
    second.id = 2;
    backlog.extend(vec![first, second, oversized]);
    assert_eq!(backlog.iter().map(|alert| alert.id).collect::<Vec<_>>(), [2]);
    assert!(backlog.bytes <= MAX_BYTES);
    assert_eq!(backlog.dropped, 2);
    backlog.clear();
    assert_eq!((backlog.bytes, backlog.iter().count(), backlog.dropped), (0, 0, 2));
}

#[test]
fn descriptions_that_fit_when_exported_do_not_displace_alerts_during_a_write_outage() {
    let mut backlog = AlertWriteBacklog::default();
    let mut verbose = alert(2, "scope");
    verbose.packet_refs = vec![3, 5];
    verbose.correlation_key = "exact-identity".into();
    verbose.detail = "example ".repeat(MAX_BYTES / 8 + 1);
    verbose.title = "title ".repeat(1_000);
    verbose.recommendation = Some("verify ".repeat(1_000));
    let snapshots = vec![alert(1, "scope"), verbose, alert(3, "scope")];
    backlog.extend(snapshots.clone());
    assert_eq!(backlog.iter().map(|alert| alert.id).collect::<Vec<_>>(), [1, 2, 3]);
    assert_eq!(backlog.dropped, 0);
    let snapshot = backlog.iter().nth(1).unwrap();
    assert!(snapshot.detail.starts_with("[Truncated] example"));
    assert_eq!(snapshot.packet_refs, [3, 5]);
    assert_eq!(snapshot.correlation_key, "exact-identity");

    let temp = tempfile::tempdir().unwrap();
    let direct = temp.path().join("direct.jsonl");
    let recovered = temp.path().join("recovered.jsonl");
    AlertJsonlWriter::open(direct.clone(), "session").unwrap().append_alerts(&snapshots).unwrap();
    AlertJsonlWriter::open(recovered.clone(), "session").unwrap().backfill_snapshots(backlog.iter()).unwrap();
    assert_eq!(std::fs::read(recovered).unwrap(), std::fs::read(direct).unwrap());
}
