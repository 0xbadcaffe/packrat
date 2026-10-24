#[test]
fn terminal_dependencies_and_bins_are_explicitly_feature_gated() {
    let manifest: toml::Value = toml::from_str(include_str!("../Cargo.toml")).unwrap();
    for dependency in ["ratatui", "crossterm", "mlua"] {
        assert_eq!(
            manifest["dependencies"][dependency]["optional"].as_bool(),
            Some(true)
        );
    }
    for name in ["packrat", "packrat-profile"] {
        let binary = manifest["bin"]
            .as_array()
            .unwrap()
            .iter()
            .find(|binary| binary["name"].as_str() == Some(name))
            .unwrap();
        assert!(
            binary["required-features"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value.as_str() == Some("terminal-ui"))
        );
    }
}

#[test]
fn the_headless_api_is_available_in_both_build_configurations() {
    let core = packrat_tui::engine::AnalysisCore::default();
    assert!(core.streams.is_empty());
    assert!(core.rule_engine.rules.is_empty());
}
