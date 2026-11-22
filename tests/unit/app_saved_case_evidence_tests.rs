use super::*;
use crate::model::project::ProjectState;

fn scoped_case() -> (String, ProjectState) {
    let mut source = App::new_for_test();
    let scope = App::new_capture_id();
    source.capture_id = Some(scope.clone());
    let mut saved = packet(1);
    saved.info = "saved evidence".into();
    source.packets.push_back(saved);
    {
        let mut core = source.core.edit();
        core.alert_center.capture_id = Some(scope.to_string());
        core.alert_center
            .record(1, "IDS", "MEDIUM", "Scoped finding", "observed");
        core.alert_center.items[0].packet_refs.push(2);
    }
    assert!(source.investigate_selected_alert());
    let state = source
        .snapshot_project("scoped", ProjectSaveMode::Lightweight)
        .unwrap();
    (scope.to_string(), state)
}

#[test]
fn restored_alert_opens_only_verified_pins_and_preserves_scope_on_resave() {
    let (scope, state) = scoped_case();
    let other_scope = App::new_capture_id();
    let file = serde_json::to_vec(&state).unwrap();
    let state: ProjectState = serde_json::from_slice(&file).unwrap();
    assert_eq!(state.pinned_packet_scopes.get(&1), Some(&scope));

    let mut restored = App::new_for_test();
    restored.capture_id = Some(other_scope);
    restored.apply_project_state(state).unwrap();
    let alert = restored.core.edit().alert_center.items[0].clone();
    assert_eq!(
        restored.alert_evidence_status(&alert),
        "1/2 retained in saved case; 1 unavailable"
    );
    restored.inject_packet(packet(2));
    assert_eq!(restored.packets.back().unwrap().no, 3);
    assert!(restored.investigate_selected_alert());
    assert_eq!(restored.worklist.active_packet_no(), Some(1));
    assert_eq!(restored.packet_by_no(1).unwrap().info, "saved evidence");
    assert!(
        restored
            .status_msg
            .as_deref()
            .unwrap()
            .contains("1 unavailable (saved case)")
    );
    let resaved = restored
        .snapshot_project("resaved", ProjectSaveMode::Lightweight)
        .unwrap();
    assert_eq!(resaved.pinned_packet_scopes.get(&1), Some(&scope));
}

#[test]
fn legacy_and_mismatched_pins_are_not_relabelled_or_linked() {
    for legacy in [true, false] {
        let (_, mut state) = scoped_case();
        if legacy {
            state.metadata.schema_version = 5;
            state.pinned_packet_scopes.clear();
        } else {
            state
                .pinned_packet_scopes
                .insert(1, App::new_capture_id().to_string());
        }
        let original_scopes = state.pinned_packet_scopes.clone();

        let mut restored = App::new_for_test();
        restored.capture_id = Some(App::new_capture_id());
        restored.apply_project_state(state).unwrap();
        assert!(restored.investigate_selected_alert());
        assert_eq!(restored.worklist.active_packet_no(), None);
        assert!(restored.worklist.retained_packet(1).is_some());
        let resaved = restored
            .snapshot_project("resaved", ProjectSaveMode::Lightweight)
            .unwrap();
        assert_eq!(resaved.pinned_packet_scopes, original_scopes);
    }
}

#[test]
fn invalid_pin_scope_metadata_is_rejected() {
    let (scope, mut state) = scoped_case();
    state.pinned_packet_scopes.insert(2, scope);
    let mut restored = App::new_for_test();
    assert!(restored.apply_project_state(state).is_err());
}
