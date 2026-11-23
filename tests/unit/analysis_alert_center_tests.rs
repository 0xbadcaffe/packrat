use super::*;

#[test]
fn deduplicates_findings_and_preserves_disposition() {
    let mut center = AlertCenter::default();
    assert!(center.record(7, "IDS", "CRITICAL", "Probe", "first"));
    assert!(!center.record(8, "IDS", "CRITICAL", "Probe", "duplicate"));
    assert_eq!(center.items[0].hit_count, 2);
    assert_eq!(center.items[0].first_packet, 7);
    assert_eq!(center.items[0].last_packet, 8);
    center.drain_pending_exports();
    assert!(!center.set_disposition(1, Some("other-capture"), AlertDisposition::Confirmed));
    assert!(center.set_disposition(1, None, AlertDisposition::Reviewing));
    assert!(center.set_disposition(1, None, AlertDisposition::Reviewing));
    let updates = center.drain_pending_exports();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].disposition, AlertDisposition::Reviewing);
    assert_eq!(center.selected_item().unwrap().disposition, AlertDisposition::Reviewing);
}

#[test]
fn first_operator_review_stays_with_the_scoped_alert_after_reopening() {
    let mut center = AlertCenter { capture_id: Some("capture-a".into()), ..Default::default() };
    center.record_correlated(1, 10.0, "IDS", "MEDIUM", "Finding", "first", "flow");
    let id = center.items[0].id;
    assert!(!center.set_disposition_at(id, Some("capture-b"), AlertDisposition::Reviewing, Some(900)));
    assert!(center.set_disposition_at(id, Some("capture-a"), AlertDisposition::Reviewing, Some(1000)));
    assert!(center.set_disposition_at(id, Some("capture-a"), AlertDisposition::Closed, Some(2000)));
    center.record_correlated(2, 11.0, "IDS", "HIGH", "Finding", "stronger", "flow");
    let latest = center.drain_pending_exports().pop().unwrap();
    assert_eq!(latest.disposition, AlertDisposition::New);
    assert_eq!(latest.first_reviewed_unix_ms, Some(1000));
    assert_eq!(latest.first_seen, 10.0);
}

#[test]
fn stronger_priority_with_new_evidence_reopens_only_resolved_findings() {
    for (previous, expected) in [
        (AlertDisposition::Benign, AlertDisposition::New),
        (AlertDisposition::Closed, AlertDisposition::New),
        (AlertDisposition::Contained, AlertDisposition::New),
        (AlertDisposition::Reviewing, AlertDisposition::Reviewing),
        (AlertDisposition::Confirmed, AlertDisposition::Confirmed),
    ] {
        let mut center = AlertCenter { automation_mode: AutomationMode::Watch, ..Default::default() };
        center.capture_id = Some("lab-capture".into());
        center.record_correlated(1, 1.0, "IDS", "MEDIUM", "Finding", "first", "flow");
        let id = center.items[0].id;
        center.set_disposition(id, Some("lab-capture"), previous);
        center.drain_pending_exports();
        assert!(center.drain_pending_pins().is_empty());
        assert!(!center.record_correlated(2, 2.0, "IDS", "MEDIUM", "Finding", "repeat", "flow"));
        assert_eq!(center.items[0].disposition, previous);
        assert!(!center.record_correlated(3, 3.0, "IDS", "HIGH", "Finding", "stronger", "flow"));
        let rows = center.drain_pending_exports();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].disposition, previous);
        assert_eq!(rows[1].disposition, expected);
        assert_eq!(rows[1].severity, "HIGH");
        assert_eq!(rows[1].id, id);
        assert_eq!(rows[1].hit_count, 3);
        assert_eq!(rows[1].packet_refs, [1, 2, 3]);
        assert_eq!(center.drain_pending_pins(), [id]);
    }
}

#[test]
fn a_priority_increase_without_new_packet_evidence_preserves_the_review_decision() {
    let mut center = AlertCenter::default();
    center.record_correlated(1, 1.0, "IDS", "HIGH", "Finding", "first", "flow");
    let id = center.items[0].id;
    assert!(center.set_disposition(id, None, AlertDisposition::Benign));
    center.record_correlated(1, 1.0, "IDS", "CRITICAL", "Finding", "same frame", "flow");
    assert_eq!(center.items[0].severity, "CRITICAL");
    assert_eq!(center.items[0].disposition, AlertDisposition::Benign);
    assert_eq!(center.items[0].packet_refs, [1]);
    let restored = serde_json::from_slice(&serde_json::to_vec(&center.items).unwrap()).unwrap();
    center.restore(restored, AutomationMode::Off);
    center.record_correlated(2, 2.0, "IDS", "HIGH", "Finding", "same priority reviewed", "flow");
    assert_eq!(center.items[0].disposition, AlertDisposition::Benign);
    center.record_correlated(3, 3.0, "IDS", "CRITICAL", "Finding", "new stronger evidence", "flow");
    assert_eq!(center.items[0].disposition, AlertDisposition::New);
    assert_eq!(center.items[0].reviewed_priority, None);
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
fn reordered_observations_extend_the_time_range_without_replacing_latest_evidence() {
    let mut center = AlertCenter::default();
    let latest_flow = AlertFlow {
        transport: AlertTransport::Tcp,
        source: "192.0.2.1:40000".parse().unwrap(),
        destination: "192.0.2.2:443".parse().unwrap(),
    };
    center.record_with_context(
        (10, &[9], Some(latest_flow)), 50.0, "IDS", "HIGH", "Finding", "latest", "flow",
    );
    center.record_with_context((11, &[8], None), 40.0, "IDS", "HIGH", "Finding", "earlier", "flow");
    center.record_with_context((12, &[], None), f64::NAN, "IDS", "HIGH", "Finding", "unknown", "flow");

    let snapshots = center.drain_pending_exports();
    let alert = snapshots.last().unwrap();
    assert_eq!(alert.hit_count, 3);
    assert_eq!(alert.first_seen, 40.0);
    assert_eq!(alert.last_seen, 50.0);
    assert_eq!(alert.first_packet, 10);
    assert_eq!(alert.last_packet, 10);
    assert_eq!(alert.packet_no, 10);
    assert_eq!(alert.detail, "latest");
    assert_eq!(alert.flow, Some(latest_flow));
    assert_eq!(alert.evidence_frame_numbers(), [8, 9, 10, 11, 12]);
}

#[test]
fn a_known_capture_time_supersedes_an_untimed_alert() {
    let mut center = AlertCenter::default();
    center.record_correlated(1, 0.0, "IDS", "HIGH", "Finding", "untimed", "scope");
    center.record_correlated(2, 15.0, "IDS", "HIGH", "Finding", "timed", "scope");
    let alert = &center.items[0];
    assert_eq!(alert.hit_count, 2);
    assert_eq!((alert.first_seen, alert.last_seen), (15.0, 15.0));
    assert_eq!((alert.first_packet, alert.last_packet), (1, 2));
}

#[test]
fn retains_bounded_packet_references_for_correlated_alerts() {
    let mut center = AlertCenter::default();
    center.record_correlated_with_evidence(
        (3, &[0, 1, 2]), 3.0, "IDS", "HIGH", "Probe", "opening evidence", "flow-a",
    );
    for packet_no in 4..=(MAX_ALERT_PACKET_REFS as u64 + 3) {
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
    assert_eq!(&alert.packet_refs[..9], &[1, 2, 3, 4, 5, 6, 7, 8, 12]);
    assert_eq!(alert.packet_refs.last(), Some(&131));
    assert_eq!(alert.hit_count, 129);

    let mut oversized = alert.clone();
    oversized.packet_refs = (1..=131).collect();
    let mut restored = AlertCenter::default();
    restored.restore(vec![oversized], AutomationMode::Off);
    assert_eq!(restored.items[0].packet_refs, alert.packet_refs);
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
fn watch_queues_new_frames_and_priority_promotions_without_duplicate_requests() {
    let mut center = AlertCenter::default();
    center.automation_mode = AutomationMode::Watch;
    center.record(10, "IDS", "MEDIUM", "Finding", "first");
    assert!(center.drain_pending_pins().is_empty());
    center.record(10, "IDS", "HIGH", "Finding", "promoted");
    assert_eq!(center.drain_pending_pins(), [1]);
    center.record(10, "IDS", "HIGH", "Finding", "repeat without new evidence");
    assert!(center.drain_pending_pins().is_empty());
    center.record(20, "IDS", "HIGH", "Finding", "new frame");
    center.record(21, "IDS", "HIGH", "Finding", "another new frame");
    assert_eq!(center.drain_pending_pins(), [1]);
    assert_eq!(center.items[0].packet_refs, [10, 20, 21]);
    center.automation_mode = AutomationMode::Off;
    center.record(22, "IDS", "HIGH", "Finding", "automatic evidence disabled");
    assert!(center.drain_pending_pins().is_empty());
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
    assert_eq!(scan.revision, 14);
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
    for &title in crate::net::security::DETECTOR_SIGNATURES {
        let source = match title {
            "SSL 3.0 selected" | "TLS 1.0 selected" | "TLS 1.1 selected" | "RC4 selected" => "TLS",
            "Telnet authentication prompt" => "EXPOSURE",
            "ARP announcement binding changed" => "ARP",
            _ => "IDS",
        };
        assert!(
            alert_provenance::lookup(source, title).is_some(),
            "missing provenance for {source}: {title}"
        );
    }
}
