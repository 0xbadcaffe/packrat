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
fn retains_bounded_packet_references_for_correlated_alerts() {
    let mut center = AlertCenter::default();
    for packet_no in 1..=(MAX_ALERT_PACKET_REFS as u64 + 3) {
        center.record_correlated(
            packet_no,
            packet_no as f64,
            "IDS",
            "HIGH",
            "Probe",
            "repeated finding",
            "flow-a",
        );
    }

    let alert = &center.items[0];
    assert_eq!(alert.packet_refs.len(), MAX_ALERT_PACKET_REFS);
    assert_eq!(alert.packet_refs.first(), Some(&4));
    assert_eq!(alert.packet_refs.last(), Some(&131));
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

#[test]
fn evicted_alert_can_recur_without_growing_the_fingerprint_index() {
    let mut center = AlertCenter::default();
    for index in 0..=MAX_ALERTS {
        assert!(center.record(index as u64 + 1, "IDS", "HIGH", format!("Probe {index}"), "detail"));
    }
    assert_eq!(center.items.len(), MAX_ALERTS);
    assert_eq!(center.fingerprints.len(), MAX_ALERTS);
    assert!(center.items.iter().all(|item| item.id != 1));

    assert!(center.record(MAX_ALERTS as u64 + 2, "IDS", "HIGH", "Probe 0", "recurrence"));
    assert_eq!(center.items.last().unwrap().title, "Probe 0");
    assert_eq!(center.items.last().unwrap().hit_count, 1);
    assert_eq!(center.fingerprints.len(), MAX_ALERTS);
    assert!(!center.record(MAX_ALERTS as u64 + 3, "IDS", "HIGH", "Probe 0", "repeat"));
    assert_eq!(center.items.last().unwrap().hit_count, 2);
}

#[test]
fn registered_rules_record_confidence_independently_of_severity() {
    use crate::analysis::alert_provenance::EvidenceConfidence;

    let mut center = AlertCenter::default();
    center.record(7, "IDS", "HIGH", "Horizontal host scan", "detected a fan-out");
    center.record(8, "AUTH", "MEDIUM", "HTTP authentication burst", "observed 401s");
    let alerts = center.drain_pending_exports();
    let scan = alerts[0].provenance.as_ref().unwrap();
    assert_eq!(scan.rule_id, "scan.horizontal");
    assert_eq!(scan.revision, 3);
    assert_eq!(scan.confidence, EvidenceConfidence::Heuristic);
    assert!(scan.verification_hint.contains("handshakes"));
    assert_eq!(
        alerts[1].provenance.as_ref().unwrap().confidence,
        EvidenceConfidence::DirectObservation
    );
    assert_eq!(alerts[1].severity, "MEDIUM");
    assert!(alerts[1].recommendation.is_none());

    let value = serde_json::to_value(&alerts[1]).unwrap();
    assert_eq!(value["provenance"]["confidence"], "direct_observation");
    let restored: AlertItem = serde_json::from_value(value).unwrap();
    assert_eq!(restored.provenance, alerts[1].provenance);
}

#[test]
fn unknown_and_legacy_alerts_do_not_inherit_provenance() {
    let mut center = AlertCenter::default();
    center.record(1, "RULE", "HIGH", "Horizontal host scan", "user-supplied name");
    assert!(center.items[0].provenance.is_none());
    center.record(2, "IDS", "HIGH", "Horizontal host scan", "new detector");
    let mut legacy = serde_json::to_value(&center.items[1]).unwrap();
    legacy.as_object_mut().unwrap().remove("provenance");
    let legacy = serde_json::from_value(legacy).unwrap();
    center.restore(vec![legacy], AutomationMode::Off);
    assert!(center.items[0].provenance.is_none());
}

#[test]
fn registered_detector_rule_ids_are_unique_and_reference_shipped_rules() {
    let mut rule_ids = HashSet::new();
    for &(source, title, id, revision, _, hint) in alert_provenance::RULES {
        assert!(rule_ids.insert(id));
        assert!(revision > 0 && !hint.is_empty());
        if source == "IDS" {
            assert!(crate::net::security::DETECTOR_SIGNATURES.contains(&title));
        }
    }
}
