use super::*;

#[test]
fn old_workspace_preferences_migrate_to_three_screen_navigation() {
    for (old, new) in [(0, 0), (1, 1), (2, 0), (3, 2), (4, 2)] {
        let mut preferences: Preferences = serde_json::from_str(&format!("{{\"startup_workspace\":{old}}}")).unwrap();
        preferences.migrate_navigation();
        assert_eq!(preferences.startup_workspace, new);
        preferences.migrate_navigation();
        assert_eq!(preferences.startup_workspace, new);
    }
}

#[test]
fn legacy_theme_only_preferences_receive_safe_defaults() {
    let preferences: Preferences = serde_json::from_str(r#"{"theme":"Matrix"}"#).unwrap();
    assert_eq!(preferences.theme, "Matrix");
    assert!(!preferences.auto_scroll);
    assert_eq!(preferences.alert_automation, 0);
    assert_eq!(preferences.startup_workspace, 0);
}
