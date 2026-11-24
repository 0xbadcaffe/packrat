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
fn incident_openings_and_retained_packets_do_not_cross_capture_scopes() {
    let mut store = IncidentStore::default();
    let first = packet(1, "203.0.113.7", "10.0.0.5");
    let second = packet(2, "203.0.113.7", "10.0.0.5");
    for (scope, trigger) in [("capture-a", &first), ("capture-b", &second)] {
        store.open_or_update_scoped(
            (IncidentSource::UserRule, Some(scope)), "rule", "finding",
            Severity::Critical, trigger, std::iter::empty(),
        );
    }
    store.retain_scoped_packet(Some("capture-b"), &packet(3, "203.0.113.7", "10.0.0.5"));
    assert_eq!(store.incidents.len(), 2);
    assert_eq!(store.incidents[0].last_packet, 1);
    assert_eq!(store.incidents[1].last_packet, 3);
}

#[test]
fn incident_openings_and_history_stay_on_the_observed_vlan_tag_path() {
    let frame = |no, tpid: u16, tci: u16| {
        let mut packet = packet(no, "203.0.113.7", "10.0.0.5");
        packet.bytes = vec![0; 12];
        packet.bytes.extend([tpid, tci, 0x88b5].into_iter().flat_map(u16::to_be_bytes));
        packet.vlan_id = Some(tci & 0x0fff);
        packet
    };
    let mut store = IncidentStore::default();
    let provider_prior = frame(1, 0x88a8, 20);
    let customer_prior = frame(2, 0x8100, 0xb014);
    let customer_open = frame(3, 0x8100, 20);
    let provider_open = frame(4, 0x88a8, 20);
    let scope = (IncidentSource::UserRule, Some("capture-a"));
    store.open_or_update_scoped(scope, "rule", "first", Severity::Critical, &customer_open,
        [provider_prior, customer_prior].into_iter());
    assert_eq!(store.active().unwrap().packet_history.iter().map(|packet| packet.no)
        .collect::<Vec<_>>(), [2, 3]);
    store.open_or_update_scoped(scope, "rule", "second", Severity::Critical, &provider_open, std::iter::empty());
    store.retain_scoped_packet(Some("capture-a"), &frame(5, 0x8100, 20));
    let mut other_interface = frame(6, 0x8100, 20);
    other_interface.capture = Some(crate::net::packet::CaptureMetadata {
        timestamp: None,
        captured_length: other_interface.bytes.len() as u32,
        wire_length: other_interface.bytes.len() as u32,
        link_type: 1, interface_id: 1, section_id: 0, interface_name: None, comments: Vec::new(),
    });
    store.retain_scoped_packet(Some("capture-a"), &other_interface);

    assert_eq!(store.incidents.len(), 2);
    assert_eq!(store.incidents[0].last_packet, 5);
    assert_eq!(store.incidents[1].last_packet, 4);
    assert_eq!(store.incidents[1].packet_history.len(), 1);

    let snapshot = store.snapshot();
    let mut inconsistent = snapshot.clone();
    let off_path = inconsistent.incidents[1].packet_history[0].clone();
    inconsistent.incidents[0].packet_history.push(off_path);
    assert!(IncidentStore::from_snapshot(inconsistent).is_err());

    let mut legacy = serde_json::to_value(snapshot).unwrap();
    legacy["incidents"][0].as_object_mut().unwrap().remove("observation_path");
    let mut restored = IncidentStore::from_snapshot(serde_json::from_value(legacy).unwrap()).unwrap();
    restored.retain_scoped_packet(Some("capture-a"), &frame(7, 0x8100, 20));
    restored.retain_scoped_packet(Some("capture-a"), &frame(8, 0x88a8, 20));
    assert_eq!(restored.incidents[0].last_packet, 5);
    assert_eq!(restored.incidents[1].last_packet, 8);
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
