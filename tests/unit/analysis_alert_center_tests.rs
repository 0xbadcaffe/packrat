use super::*;

#[test]
fn deduplicates_findings_and_preserves_disposition() {
    let mut center = AlertCenter::default();
    assert!(center.record(7, "IDS", "CRITICAL", "Probe", "first"));
    assert!(!center.record(8, "IDS", "CRITICAL", "Probe", "duplicate"));
    assert_eq!(center.items[0].hit_count, 2);
    assert_eq!(center.items[0].first_packet, 7);
    assert_eq!(center.items[0].last_packet, 8);
    assert!(center.set_selected_disposition(AlertDisposition::Reviewing));
    assert_eq!(center.selected_item().unwrap().disposition, AlertDisposition::Reviewing);
}

#[test]
fn correlation_keys_keep_distinct_conversations_separate() {
    let mut center = AlertCenter::default();
    assert!(center.record_correlated(1, 1.0, "IDS", "HIGH", "Probe", "first host", "host-a"));
    assert!(center.record_correlated(2, 2.0, "IDS", "HIGH", "Probe", "second host", "host-b"));
    assert!(!center.record_correlated(3, 3.0, "IDS", "HIGH", "Probe", "first host again", "host-a"));
    assert_eq!(center.items.len(), 2);
    assert_eq!(center.items[0].hit_count, 2);
    assert_eq!(center.items[0].last_seen, 3.0);
}

#[test]
fn severity_filter_resets_and_bounds_selection() {
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "LOW", "Low", "detail");
    center.record(2, "IDS", "CRITICAL", "Critical", "detail");
    center.next();
    center.cycle_severity_filter();
    assert_eq!(center.severity_filter, AlertSeverityFilter::Critical);
    assert_eq!(center.selected, 0);
    assert_eq!(center.selected_item().unwrap().packet_no, 2);
    center.next();
    assert_eq!(center.selected, 0);
}

#[test]
fn watch_pins_high_findings_and_triage_adds_deterministic_advice() {
    let mut center = AlertCenter::default();
    center.automation_mode = AutomationMode::Watch;
    center.record(1, "IDS", "LOW", "Low", "detail");
    center.record(2, "IDS", "HIGH", "High", "detail");
    assert_eq!(center.drain_pending_pins(), vec![2]);
    assert!(center.items[1].recommendation.is_none());

    center.automation_mode = AutomationMode::Triage;
    center.record(3, "IOC", "HIGH", "Indicator", "detail");
    assert_eq!(center.items[2].priority, 80);
    assert!(center.items[2].recommendation.as_deref().unwrap().contains("provenance"));
}

#[test]
fn restored_alerts_continue_with_unique_ids_and_deduplication() {
    let mut original = AlertCenter::default();
    original.record(7, "IDS", "HIGH", "Probe", "detail");
    original.items[0].disposition = AlertDisposition::Reviewing;

    let mut restored = AlertCenter::default();
    restored.restore(original.items.clone(), AutomationMode::Triage);
    assert!(!restored.record(7, "IDS", "HIGH", "Probe", "duplicate"));
    assert_eq!(restored.items[0].hit_count, 2);
    assert!(restored.record(8, "IDS", "HIGH", "Different probe", "new finding"));
    assert_eq!(restored.items[1].id, 2);
    assert_eq!(restored.items[0].disposition, AlertDisposition::Reviewing);
}
