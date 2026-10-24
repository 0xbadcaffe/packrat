use super::*;

#[test]
fn background_restore_preserves_acknowledgements_without_reopening_alerts() {
    let mut source = App::new_for_test();
    source.inject_packet(packet(1));
    source.open_user_rule_incident(&packet(1), "rule", "rule", "finding", false);
    source.open_active_incident_analysis();
    source.acknowledge_active_incident().unwrap();
    let state = source
        .snapshot_project("case", ProjectSaveMode::Portable)
        .unwrap();
    let mut restored = App::new_for_test();
    restored.start_background_analysis().unwrap();
    restored.apply_project_state(state).unwrap();
    assert!(
        restored
            .snapshot_project("pending", ProjectSaveMode::Portable)
            .is_err()
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !restored.analysis_idle() {
        restored.poll_analysis();
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert!(!restored.alert_overlay_open);
    assert_eq!(restored.packets.len(), 1);
    assert_eq!(
        restored.query_core(|core| core.incidents.active().is_none()),
        Some(true)
    );
    assert_eq!(
        restored.query_core(|core| core.incidents.incidents[0].reviewed),
        Some(true)
    );
    assert!(restored.evidence_vault.exports.is_empty());
    assert!(restored.traffic_latch.actions.is_empty());
}

fn packet(no: u64) -> Packet {
    Packet {
        capture: None,
        no,
        timestamp: 1.0,
        src: "192.0.2.1".into(),
        dst: "198.51.100.2".into(),
        protocol: "UDP".into(),
        length: 4,
        info: "project test".into(),
        src_port: Some(50000),
        dst_port: Some(53),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes: vec![1, 2, 3, 4],
    }
}

#[test]
fn portable_snapshot_embeds_packets_but_lightweight_does_not() {
    let mut app = App::new_for_test();
    app.inject_packet(packet(1));

    let portable = app
        .snapshot_project("portable", ProjectSaveMode::Portable)
        .unwrap();
    assert_eq!(portable.embedded_packets.len(), 1);
    assert_eq!(portable.embedded_packets[0].bytes, vec![1, 2, 3, 4]);
    let lightweight = app
        .snapshot_project("light", ProjectSaveMode::Lightweight)
        .unwrap();
    assert!(lightweight.embedded_packets.is_empty());
}

#[test]
fn pinned_packet_survives_live_eviction_and_both_project_modes() {
    let mut app = App::new_for_test();
    app.retain_packet_display(packet(1));
    app.mark_selected_packet_for_investigation();
    for no in 2..=MAX_PACKETS as u64 + 1 {
        app.retain_packet_display(packet(no));
    }
    assert!(app.packets.iter().all(|packet| packet.no != 1));
    assert_eq!(
        app.active_investigation_packet().unwrap().bytes,
        [1, 2, 3, 4]
    );
    for mode in [ProjectSaveMode::Lightweight, ProjectSaveMode::Portable] {
        let state = app.snapshot_project("retained", mode).unwrap();
        let serialized = serde_json::to_vec(&state).unwrap();
        let restored = serde_json::from_slice(&serialized).unwrap();
        let tray = restore_investigation_tray(&restored).unwrap();
        assert_eq!(tray.active_packet_no(), Some(1));
        assert_eq!(tray.retained_packet(1).unwrap().bytes, [1, 2, 3, 4]);
    }
    app.remove_active_worklist_packet();
    assert!(app.packet_by_no(1).is_none());
    assert_eq!(app.worklist.retained_bytes, 0);
}

#[test]
fn pin_limits_fail_without_losing_or_silently_evicting_evidence() {
    let mut tray = InvestigationTray::default();
    for no in 0..InvestigationTray::MAX_RETAINED_PACKETS as u64 {
        assert!(tray.pin_packet(&packet(no)).unwrap());
    }
    let used = tray.retained_bytes;
    assert!(!tray.pin_packet(&packet(0)).unwrap());
    assert_eq!(tray.retained_bytes, used);
    assert!(tray.pin_packet(&packet(2048)).is_err());
    assert!(tray.retained_packet(0).is_some());
    tray.remove_active();
    assert!(tray.pin_packet(&packet(2048)).unwrap());

    let mut full = InvestigationTray::default();
    full.retained_bytes = InvestigationTray::MAX_RETAINED_BYTES;
    assert!(full.pin_packet(&packet(1)).is_err());
    assert!(full.items.is_empty());
}

#[test]
fn legacy_portable_projects_restore_pins_before_live_ring_eviction() {
    let mut state = crate::model::project::ProjectState::new("old", ProjectSaveMode::Portable);
    state.investigation_items = vec![SavedInvestigationItem::Packet(1)];
    state.active_investigation = Some(0);
    state.embedded_packets = vec![packet(1), packet(2)];
    let tray = restore_investigation_tray(&state).unwrap();
    assert_eq!(tray.retained_packet(1).unwrap().no, 1);
    assert!(tray.retained_packet(2).is_none());
}

#[test]
fn explicit_auto_contain_rule_cannot_enforce_an_offline_incident() {
    let mut app = App::new_for_test();
    app.traffic_latch.mode = LatchMode::Automatic;
    app.latch_helper_path = Some("/must-not-execute".into());
    app.inject_packet(packet(1));
    app.open_user_rule_incident(&packet(1), "auto-rule", "auto", "test", true);
    assert_eq!(app.traffic_latch.actions.len(), 1);
    assert_eq!(
        app.traffic_latch.actions[0].status,
        crate::analysis::traffic_latch::LatchStatus::Observed
    );
    app.approve_active_latch();
    assert_eq!(
        app.traffic_latch.actions[0].status,
        crate::analysis::traffic_latch::LatchStatus::Observed
    );
}

#[test]
fn cases_restore_reviewed_incidents_and_correlated_impact_without_side_effects() {
    use crate::analysis::impact::{EndpointCategory, EndpointEvidence, ImpactConfidence};
    let mut source = App::new_for_test();
    source.inject_packet(packet(1));
    source.open_user_rule_incident(&packet(1), "rule", "rule", "finding", true);
    let id = source.core.edit().incidents.active().unwrap().id;
    source.core.edit().incidents.mark_active_reviewed();
    source.core.edit().incidents.acknowledge_active().unwrap();
    source.core.edit().endpoint_evidence.push(EndpointEvidence {
        incident_id: id,
        target: "198.51.100.2".into(),
        source: "audit".into(),
        evidence_id: "event-17".into(),
        category: EndpointCategory::File,
        subject: "/srv/private.csv".into(),
        action: "read".into(),
        successful: true,
    });

    for mode in [ProjectSaveMode::Lightweight, ProjectSaveMode::Portable] {
        let state = source.snapshot_project("case", mode).unwrap();
        let json = serde_json::to_vec(&state).unwrap();
        let directory =
            std::env::temp_dir().join(format!("packrat-restore-{}", rand::random::<u64>()));
        let mut restored = App::new_for_test();
        restored.packet_archive =
            Some(crate::storage::packet_archive::ArchiveWorker::open(&directory).unwrap());
        restored.evidence_vault = EvidenceVault::new(directory.join("evidence"));
        restored.traffic_latch.mode = LatchMode::Automatic;
        restored.latch_helper_path = Some("/must-not-run".into());
        restored.filter.input = "stale filter".into();
        restored
            .apply_project_state(serde_json::from_slice(&json).unwrap())
            .unwrap();
        assert!(restored.filter.input.is_empty());
        assert!(restored.core.edit().incidents.active().is_none());
        assert_eq!(restored.core.edit().incidents.incidents[0].id, id);
        assert!(restored.core.edit().incidents.incidents[0].reviewed);
        assert_eq!(
            restored.core.edit().incidents.incidents[0].packet_history[0].bytes,
            [1, 2, 3, 4]
        );
        let report = restored
            .query_core(|core| {
                crate::analysis::impact::correlate(
                    &core.incidents.incidents[0],
                    &core.endpoint_evidence,
                )
            })
            .unwrap();
        assert!(!report.compromise_confirmed);
        assert!(
            report
                .evidence
                .iter()
                .any(|entry| entry.subject == "/srv/private.csv"
                    && entry.confidence == ImpactConfidence::Observed)
        );
        assert!(restored.traffic_latch.actions.is_empty());
        assert!(restored.evidence_vault.exports.is_empty());
        assert!(!directory.join("evidence").exists());
        restored.packet_archive.as_mut().unwrap().finish().unwrap();
        let archive =
            crate::storage::packet_archive::PacketArchive::open_readonly(&directory).unwrap();
        assert_eq!(archive.count().unwrap(), 0);
        drop(archive);
        let new_id = restored.core.edit().incidents.open_or_update(
            IncidentSource::UserRule,
            "new",
            "new",
            EvidenceSeverity::Critical,
            &packet(2),
            std::iter::empty(),
        );
        assert!(new_id > id);
        assert!(!restored.live_response_eligible);
        drop(restored);
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn invalid_saved_incidents_do_not_replace_the_open_investigation() {
    let mut app = App::new_for_test();
    app.inject_packet(packet(99));
    let mut state = app
        .snapshot_project("bad", ProjectSaveMode::Portable)
        .unwrap();
    state.incident_state.as_mut().unwrap().last_id = u64::MAX;
    assert!(app.apply_project_state(state).is_err());
    assert_eq!(app.packets[0].no, 99);
}
