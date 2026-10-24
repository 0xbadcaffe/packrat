use super::*;

fn packet(no: u64, src: &str, dst: &str) -> Packet {
    Packet { capture: None,
        no,
        timestamp: no as f64,
        src: src.into(),
        dst: dst.into(),
        protocol: "TCP".into(),
        length: 60,
        info: String::new(),
        src_port: Some(12345),
        dst_port: Some(443),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes: Vec::new(),
    }
}

#[test]
fn retains_conversation_history_and_requires_review_before_acknowledgement() {
    let mut store = IncidentStore::default();
    let current = packet(3, "203.0.113.7", "10.0.0.5");
    store.open_or_update(
        IncidentSource::IndustrySignature,
        "Test signature",
        "test finding",
        Severity::Critical,
        &current,
        vec![packet(1, "203.0.113.7", "10.0.0.5"), packet(2, "10.0.0.5", "203.0.113.7")].into_iter(),
    );

    assert_eq!(store.active().unwrap().packet_history.len(), 3);
    assert!(store.acknowledge_active().is_err());
    assert!(store.mark_active_reviewed());
    assert!(store.acknowledge_active().is_ok());
    assert!(!store.has_pending());
    assert_eq!(store.incidents[0].status, IncidentStatus::Acknowledged);
}

#[test]
fn deduplicates_repeated_pending_finding() {
    let mut store = IncidentStore::default();
    let first = packet(1, "203.0.113.7", "10.0.0.5");
    let second = packet(2, "203.0.113.7", "10.0.0.5");
    store.open_or_update(IncidentSource::UserRule, "rule-1", "first", Severity::Critical, &first, std::iter::empty());
    store.open_or_update(IncidentSource::UserRule, "rule-1", "second", Severity::Critical, &second, std::iter::empty());

    assert_eq!(store.incidents.len(), 1);
    assert_eq!(store.active().unwrap().last_packet, 2);
}

#[test]
fn saved_incidents_validate_identifiers_and_restore_pending_review() {
    let mut store = IncidentStore::default();
    let packet = packet(1, "203.0.113.7", "10.0.0.5");
    let id = store.open_or_update(IncidentSource::UserRule, "rule", "finding",
        Severity::Critical, &packet, std::iter::empty());
    let snapshot = store.snapshot();
    assert_eq!(IncidentStore::from_snapshot(snapshot.clone()).unwrap().active().unwrap().id, id);
    let mut duplicate = snapshot.clone();
    duplicate.incidents.push(duplicate.incidents[0].clone());
    assert!(IncidentStore::from_snapshot(duplicate).is_err());
    let mut invalid = snapshot;
    invalid.last_id = 0;
    assert!(IncidentStore::from_snapshot(invalid).is_err());
}
