use super::*;

#[test]
fn offline_detector_state_disables_later_live_enforcement_until_cleared() {
    let mut app = App::new_for_test();
    app.traffic_latch.mode = LatchMode::Automatic;
    app.inject_packet(packet(1));
    app.capturing = true;
    app.selected_iface = "test-live".into();
    app.ingest_packet(live_critical_packet());
    assert_eq!(app.traffic_latch.actions[0].status, LatchStatus::Observed);
    app.clear_packets();
    app.capturing = true;
    app.ingest_packet(live_critical_packet());
    assert_eq!(
        app.traffic_latch.actions[0].status,
        LatchStatus::PendingApproval
    );
}

#[test]
fn queued_packets_from_another_interface_cannot_trigger_enforcement() {
    let mut app = App::new_for_test();
    app.capturing = true;
    app.selected_iface = "new-interface".into();
    app.traffic_latch.mode = LatchMode::Automatic;
    app.ingest_packet(live_critical_packet());
    assert_eq!(app.traffic_latch.actions[0].status, LatchStatus::Observed);
}

// ─── Workspace navigation ────────────────────────────────────────────────────

#[rstest]
#[case(KeyCode::Char('1'), Tab::Packets)]
#[case(KeyCode::Char('2'), Tab::Investigate)]
#[case(KeyCode::Char('3'), Tab::Notebook)]
#[case(KeyCode::Char('4'), Tab::Scanner)]
#[case(KeyCode::Char('5'), Tab::Notebook)]
#[tokio::test]
async fn numeric_workspace_switch(#[case] code: KeyCode, #[case] expected: Tab) {
    let mut app = App::new_for_test();
    event::handle(&mut app, key(code));
    assert_eq!(app.active_tab, expected);
}

#[tokio::test]
async fn tab_opens_workspace_view_menu_and_enter_selects_view() {
    let mut app = App::new_for_test();
    event::handle(&mut app, key(KeyCode::Tab));
    assert!(app.view_menu_open);

    event::handle(&mut app, key(KeyCode::Down));
    event::handle(&mut app, key(KeyCode::Enter));
    assert!(!app.view_menu_open);
    assert_eq!(app.active_tab, Tab::Flows);
}

#[tokio::test]
async fn escape_returns_to_workspace_home() {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Objects;
    event::handle(&mut app, key(KeyCode::Esc));
    assert_eq!(app.active_tab, Workspace::Inspect.home());
}

#[tokio::test]
async fn alt_left_returns_to_previous_screen_across_workspaces() {
    let mut app = App::new_for_test();
    event::handle(&mut app, key(KeyCode::Char('S')));
    event::handle(&mut app, key(KeyCode::Char('N')));
    assert_eq!(app.active_tab, Tab::Notebook);

    event::handle(&mut app, alt(KeyCode::Left));
    assert_eq!(app.active_tab, Tab::Security);
    event::handle(&mut app, alt(KeyCode::Left));
    assert_eq!(app.active_tab, Tab::Packets);
}

#[test]
fn navigation_history_is_bounded_and_ignores_current_screen() {
    let mut app = App::new_for_test();
    app.navigate_to(Tab::Packets);
    assert!(app.navigation_history.is_empty());

    for index in 0..40 {
        app.navigate_to(if index % 2 == 0 {
            Tab::Flows
        } else {
            Tab::Packets
        });
    }
    assert_eq!(app.navigation_history.len(), 32);
}

#[rstest]
#[case(KeyCode::Char('H'), Tab::Hosts)]
#[case(KeyCode::Char('N'), Tab::Notebook)]
#[case(KeyCode::Char('T'), Tab::TlsAnalysis)]
#[case(KeyCode::Char('O'), Tab::Objects)]
#[case(KeyCode::Char('R'), Tab::Rules)]
#[case(KeyCode::Char('W'), Tab::Workbench)]
#[case(KeyCode::Char('G'), Tab::OperatorGraph)]
#[case(KeyCode::Char('D'), Tab::Diff)]
#[tokio::test]
async fn letter_tab_switch(#[case] code: KeyCode, #[case] expected: Tab) {
    let mut app = App::new_for_test();
    event::handle(&mut app, key(code));
    assert_eq!(app.active_tab, expected);
}

// ─── Global overlays ──────────────────────────────────────────────────────────

#[tokio::test]
async fn backslash_opens_theme_picker() {
    let mut app = App::new_for_test();
    event::handle(&mut app, key(KeyCode::Char('\\')));
    assert!(app.theme_picker_open);
}

#[tokio::test]
async fn comma_opens_settings_window() {
    let mut app = App::new_for_test();
    event::handle(&mut app, key(KeyCode::Char(',')));
    assert!(app.settings_open);
    event::handle(&mut app, key(KeyCode::Esc));
    assert!(!app.settings_open);
}

#[tokio::test]
async fn settings_enter_toggles_packet_following() {
    let mut app = App::new_for_test();
    event::handle(&mut app, key(KeyCode::Char(',')));
    event::handle(&mut app, key(KeyCode::Char('j')));
    event::handle(&mut app, key(KeyCode::Enter));
    assert!(app.auto_scroll);
}

#[test]
fn packet_following_keeps_selection_on_newest_match() {
    let mut app = App::new_for_test();
    app.auto_scroll = true;
    app.inject_packet(packet(1));
    app.inject_packet(packet(2));
    assert_eq!(app.selected, Some(1));

    app.auto_scroll = false;
    app.inject_packet(packet(3));
    assert_eq!(app.selected, Some(1));
}

#[tokio::test]
async fn settings_enter_cycles_latch_mode_from_defense_section() {
    let mut app = App::new_for_test();
    event::handle(&mut app, key(KeyCode::Char(',')));
    event::handle(&mut app, key(KeyCode::Char('j')));
    event::handle(&mut app, key(KeyCode::Char('j')));
    event::handle(&mut app, key(KeyCode::Char('j')));
    event::handle(&mut app, key(KeyCode::Char('j')));
    event::handle(&mut app, key(KeyCode::Enter));
    assert_eq!(app.traffic_latch.mode, LatchMode::Preview);
}

#[tokio::test]
async fn settings_cycles_alert_automation_without_enabling_containment() {
    let mut app = App::new_for_test();
    event::handle(&mut app, key(KeyCode::Char(',')));
    for _ in 0..3 {
        event::handle(&mut app, key(KeyCode::Char('j')));
    }
    event::handle(&mut app, key(KeyCode::Enter));
    assert_eq!(
        app.alert_center.automation_mode,
        packrat_tui::analysis::alert_center::AutomationMode::Watch,
    );
    assert_eq!(app.traffic_latch.mode, LatchMode::Monitor);
}

#[tokio::test]
async fn settings_adjust_guard_timeout_with_arrow_keys() {
    let mut app = App::new_for_test();
    event::handle(&mut app, key(KeyCode::Char(',')));
    for _ in 0..5 {
        event::handle(&mut app, key(KeyCode::Char('j')));
    }
    let initial = app.traffic_latch.expires_seconds;
    event::handle(&mut app, key(KeyCode::Right));
    assert_eq!(app.traffic_latch.expires_seconds, initial + 60);
    event::handle(&mut app, key(KeyCode::Left));
    assert_eq!(app.traffic_latch.expires_seconds, initial);
}

#[tokio::test]
async fn help_navigation_scrolls_without_closing() {
    let mut app = App::new_for_test();
    app.show_help = true;
    event::handle(&mut app, key(KeyCode::PageDown));
    assert!(app.show_help);
    assert_eq!(app.help_scroll, 10);
    event::handle(&mut app, key(KeyCode::PageUp));
    assert_eq!(app.help_scroll, 0);
}

#[test]
fn watch_mode_auto_pins_only_high_priority_alerts() {
    let mut app = App::new_for_test();
    app.alert_center.automation_mode = packrat_tui::analysis::alert_center::AutomationMode::Watch;
    app.alert_center.record(1, "IDS", "LOW", "low", "detail");
    app.alert_center.record(2, "IDS", "HIGH", "high", "detail");
    for id in app.alert_center.drain_pending_pins() {
        app.worklist
            .add(packrat_tui::app::InvestigationItem::Alert(id));
    }
    assert_eq!(
        app.worklist.items,
        vec![packrat_tui::app::InvestigationItem::Alert(2)]
    );
}

#[tokio::test]
async fn exclamation_engages_guard_kill_switch_from_any_screen() {
    let mut app = App::new_for_test();
    app.traffic_latch.mode = LatchMode::Automatic;
    event::handle(&mut app, key(KeyCode::Char('!')));
    assert!(app.traffic_latch.emergency_stop);
    assert_eq!(app.traffic_latch.mode, LatchMode::Monitor);
}

#[test]
fn guard_simulation_requires_independent_critical_signals() {
    use packrat_tui::analysis::incident::IncidentSource;
    use packrat_tui::analysis::traffic_latch::LatchStatus;
    use packrat_tui::model::evidence::Severity;

    let mut app = App::new_for_test();
    let finding = packet(1);
    app.incidents.open_or_update(
        IncidentSource::IndustrySignature,
        "detector-a",
        "first",
        Severity::Critical,
        &finding,
        std::iter::empty(),
    );
    app.simulate_guard_response();
    assert_eq!(app.response_preview[0].status, LatchStatus::PendingApproval);

    app.incidents.open_or_update(
        IncidentSource::IndustrySignature,
        "detector-b",
        "second",
        Severity::Critical,
        &finding,
        std::iter::empty(),
    );
    app.simulate_guard_response();
    assert!(
        app.response_preview
            .iter()
            .all(|action| action.status == LatchStatus::Previewed)
    );
}

#[tokio::test]
async fn selected_packet_can_be_marked_and_investigated() {
    let mut app = App::new_for_test();
    app.inject_packet(packet(1));
    app.inject_packet(packet(2));
    app.selected = Some(0);

    event::handle(&mut app, key(KeyCode::Char('m')));
    assert_eq!(app.worklist.packet_nos(), vec![1]);

    app.selected = Some(1);
    event::handle(&mut app, key(KeyCode::Enter));
    assert_eq!(app.active_tab, Tab::Investigate);
    assert_eq!(app.worklist.active_packet_no(), Some(2));

    event::handle(&mut app, key(KeyCode::Char('p')));
    assert_eq!(app.worklist.active_packet_no(), Some(1));
}
