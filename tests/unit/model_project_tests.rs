use super::*;
use crate::analysis::alert_center::{AlertDisposition, AlertItem};

#[test]
fn older_projects_load_with_empty_operational_state() {
    let state = ProjectState::new("legacy", ProjectSaveMode::Lightweight);
    let mut json = serde_json::to_value(state).unwrap();
    let object = json.as_object_mut().unwrap();
    for field in [
        "alert_items",
        "alert_automation",
        "investigation_items",
        "active_investigation",
        "investigation_tray_open",
        "guard_simulation",
        "active_tab",
        "embedded_packets",
        "pinned_packets",
        "incident_state",
        "endpoint_evidence",
    ] {
        object.remove(field);
    }

    let restored: ProjectState = serde_json::from_value(json).unwrap();
    assert!(restored.alert_items.is_empty());
    assert_eq!(restored.alert_automation, AutomationMode::Off);
    assert!(restored.investigation_items.is_empty());
    assert!(restored.guard_simulation.is_empty());
    assert_eq!(restored.active_tab, 0);
}

#[test]
fn operational_investigation_state_round_trips() {
    let mut state = ProjectState::new("case", ProjectSaveMode::Portable);
    state.alert_automation = AutomationMode::Triage;
    state.alert_items.push(AlertItem {
        id: 7,
        packet_no: 42,
        source: "IDS".into(),
        severity: "HIGH".into(),
        title: "Probe".into(),
        detail: "Repeated connection attempts".into(),
        disposition: AlertDisposition::Reviewing,
        priority: 80,
        recommendation: Some("Inspect the stream".into()),
        correlation_key: "203.0.113.9>10.0.0.5".into(),
        hit_count: 3,
        first_packet: 40,
        last_packet: 42,
        first_seen: 1.0,
        last_seen: 3.0,
    });
    state.investigation_items = vec![
        SavedInvestigationItem::Packet(42),
        SavedInvestigationItem::Host("203.0.113.9".into()),
    ];
    state.active_investigation = Some(1);
    state.investigation_tray_open = true;
    state.active_tab = 9;
    state.embedded_packets.push(Packet { capture: None,
        no: 42,
        timestamp: 3.0,
        src: "203.0.113.9".into(),
        dst: "10.0.0.5".into(),
        protocol: "TCP".into(),
        length: 4,
        info: "portable evidence".into(),
        src_port: Some(40000),
        dst_port: Some(443),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes: vec![1, 2, 3, 4],
    });

    let restored: ProjectState = serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
    assert_eq!(restored.alert_items[0].disposition, AlertDisposition::Reviewing);
    assert_eq!(restored.alert_automation, AutomationMode::Triage);
    assert_eq!(restored.investigation_items, state.investigation_items);
    assert_eq!(restored.active_investigation, Some(1));
    assert!(restored.investigation_tray_open);
    assert_eq!(restored.active_tab, 9);
    assert_eq!(restored.embedded_packets.len(), 1);
    assert_eq!(restored.embedded_packets[0].bytes, vec![1, 2, 3, 4]);
}
