use super::*;
use crate::analysis::alert_center::AlertCenter;

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
    oversized.detail = String::with_capacity(MAX_BYTES + 1);
    oversized.detail.push('x');
    let mut first = alert(1, "scope");
    first.detail = "x".repeat(MAX_BYTES / 2 + 1);
    let mut second = first.clone();
    second.id = 2;
    backlog.extend(vec![first, second, oversized]);
    assert_eq!(backlog.iter().map(|alert| alert.id).collect::<Vec<_>>(), [2]);
    assert!(backlog.bytes <= MAX_BYTES);
    assert_eq!(backlog.dropped, 2);
    backlog.clear();
    assert_eq!((backlog.bytes, backlog.iter().count(), backlog.dropped), (0, 0, 2));
}
