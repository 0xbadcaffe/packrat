use super::*;

// ─── PCAP import ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn l_key_activates_pcap_import() {
    let mut app = App::new_for_test();
    event::handle(&mut app, shift('L'));
    assert!(app.pcap_import_editing);
}

#[tokio::test]
async fn pcap_import_esc_cancels() {
    let mut app = App::new_for_test();
    app.pcap_import_editing = true;
    app.pcap_import_path = "/tmp/test.pcap".to_string();
    event::handle(&mut app, key(KeyCode::Esc));
    assert!(!app.pcap_import_editing);
    assert!(app.pcap_import_path.is_empty());
}

#[tokio::test]
async fn pcap_import_chars_go_to_path() {
    let mut app = App::new_for_test();
    app.pcap_import_editing = true;
    for c in "/tmp/test".chars() {
        event::handle(&mut app, key(KeyCode::Char(c)));
    }
    assert_eq!(app.pcap_import_path, "/tmp/test");
}

// ─── Help closes from various keys ───────────────────────────────────────────

#[rstest]
#[case(KeyCode::Esc)]
#[case(KeyCode::Char('h'))]
#[case(KeyCode::Char('q'))]
#[tokio::test]
async fn help_closes_on_key(#[case] code: KeyCode) {
    let mut app = App::new_for_test();
    app.show_help = true;
    event::handle(&mut app, key(code));
    assert!(!app.show_help);
}

// ─── Stream overlay ───────────────────────────────────────────────────────────

#[rstest]
#[case(KeyCode::Esc)]
#[case(KeyCode::Char('q'))]
#[tokio::test]
async fn stream_overlay_closes_on_key(#[case] code: KeyCode) {
    let mut app = App::new_for_test();
    app.stream_overlay = Some(packrat_tui::analysis::stream::StreamOverlayState::new(
        "test".to_string(),
        vec![],
    ));
    event::handle(&mut app, key(code));
    assert!(app.stream_overlay.is_none());
}

#[tokio::test]
async fn stream_overlay_searches_and_navigates_matches() {
    let mut app = App::new_for_test();
    app.stream_overlay = Some(packrat_tui::analysis::stream::StreamOverlayState::new(
        "test".into(),
        vec![
            (true, b"GET /admin".to_vec()),
            (false, b"ADMIN denied".to_vec()),
        ],
    ));
    event::handle(&mut app, key(KeyCode::Char('/')));
    for character in "admin".chars() {
        event::handle(&mut app, key(KeyCode::Char(character)));
    }
    event::handle(&mut app, key(KeyCode::Enter));
    assert_eq!(app.stream_overlay.as_ref().unwrap().matches.len(), 2);
    event::handle(&mut app, key(KeyCode::Char('n')));
    assert_eq!(app.stream_overlay.as_ref().unwrap().selected_match, 1);
}

// ─── Strings search ───────────────────────────────────────────────────────────

#[tokio::test]
async fn strings_search_chars_accumulate() {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Strings;
    app.strings_search_active = true;
    event::handle(&mut app, key(KeyCode::Char('p')));
    event::handle(&mut app, key(KeyCode::Char('a')));
    event::handle(&mut app, key(KeyCode::Char('s')));
    event::handle(&mut app, key(KeyCode::Char('s')));
    assert_eq!(app.strings_filter, "pass");
}

#[tokio::test]
async fn strings_search_backspace_deletes() {
    let mut app = App::new_for_test();
    app.strings_search_active = true;
    app.strings_filter = "pass".to_string();
    event::handle(&mut app, key(KeyCode::Backspace));
    assert_eq!(app.strings_filter, "pas");
}

#[tokio::test]
async fn strings_search_esc_clears_and_deactivates() {
    let mut app = App::new_for_test();
    app.strings_search_active = true;
    app.strings_filter = "pass".to_string();
    event::handle(&mut app, key(KeyCode::Esc));
    assert!(!app.strings_search_active);
    assert!(app.strings_filter.is_empty());
}

#[rstest]
#[case(KeyCode::Char('o'), "Objects")]
#[case(KeyCode::Char('y'), "YaraRules")]
#[case(KeyCode::Char('m'), "YaraMatches")]
#[tokio::test]
async fn objects_subtab_keys(#[case] code: KeyCode, #[case] expected: &str) {
    let mut app = objects_app();
    event::handle(&mut app, key(code));
    let got = format!("{:?}", app.objects_subtab);
    assert_eq!(got, expected);
}

#[tokio::test]
async fn objects_scroll_j_increments() {
    let mut app = objects_app();
    app.objects_scroll = 0;
    event::handle(&mut app, key(KeyCode::Char('j')));
    assert_eq!(app.objects_scroll, 1);
}

#[tokio::test]
async fn objects_g_resets_all_scrolls() {
    let mut app = objects_app();
    app.objects_scroll = 5;
    app.yara_rules_scroll = 3;
    app.yara_matches_scroll = 7;
    event::handle(&mut app, key(KeyCode::Char('g')));
    assert_eq!(app.objects_scroll, 0);
    assert_eq!(app.yara_rules_scroll, 0);
    assert_eq!(app.yara_matches_scroll, 0);
}

// ─── Tab index round-trip ─────────────────────────────────────────────────────

#[rstest]
#[case(Tab::Packets)]
#[case(Tab::Investigate)]
#[case(Tab::Analysis)]
#[case(Tab::Strings)]
#[case(Tab::Dynamic)]
#[case(Tab::Visualize)]
#[case(Tab::Flows)]
#[case(Tab::Craft)]
#[case(Tab::Traceroute)]
#[case(Tab::Security)]
#[case(Tab::Scanner)]
#[case(Tab::Hosts)]
#[case(Tab::Notebook)]
#[case(Tab::TlsAnalysis)]
#[case(Tab::Objects)]
#[case(Tab::Rules)]
#[case(Tab::Workbench)]
#[case(Tab::OperatorGraph)]
#[case(Tab::Diff)]
fn tab_index_roundtrip(#[case] tab: Tab) {
    let idx = tab.index();
    assert_eq!(Tab::from_index(idx), tab);
}

#[test]
fn tab_count_matches_variants() {
    assert_eq!(Tab::COUNT, 19);
    assert_eq!(Workspace::COUNT, 3);
    assert!(Workspace::Case.views().contains(&Tab::Notebook));
    assert!(Workspace::Case.views().contains(&Tab::Craft));
}

#[test]
fn every_specialist_view_is_reachable_from_the_three_workspaces() {
    let views: Vec<_> = (0..Workspace::COUNT)
        .flat_map(|index| Workspace::from_index(index).views())
        .collect();
    assert_eq!(views.len(), Tab::COUNT);
    for index in 0..Tab::COUNT {
        assert_eq!(
            views
                .iter()
                .filter(|view| ***view == Tab::from_index(index))
                .count(),
            1
        );
    }
}

#[test]
fn command_palette_preserves_the_investigation_context_and_history() {
    let mut app = App::new_for_test();
    app.inject_packet(packet(1));
    app.mark_selected_packet_for_investigation();
    let context = app.worklist.active_packet_no();
    app.open_search();
    app.search_query = "scanner".into();
    app.run_search();
    app.search_selected = app
        .search_results
        .iter()
        .position(|result| result.source == "View" && result.jump_tab == Tab::Scanner)
        .unwrap();
    app.search_jump();
    assert_eq!(app.active_tab, Tab::Scanner);
    assert_eq!(app.worklist.active_packet_no(), context);
    assert!(app.navigate_back());
    assert_eq!(app.active_tab, Tab::Packets);
}

#[tokio::test]
async fn escape_returns_through_context_without_creating_a_navigation_loop() {
    let mut app = App::new_for_test();
    app.navigate_to(Tab::Hosts);
    app.navigate_to(Tab::Objects);
    event::handle(&mut app, key(KeyCode::Esc));
    assert_eq!(app.active_tab, Tab::Hosts);
    event::handle(&mut app, key(KeyCode::Esc));
    assert_eq!(app.active_tab, Tab::Packets);
    event::handle(&mut app, key(KeyCode::Esc));
    assert_eq!(app.active_tab, Tab::Packets);
}

#[test]
fn packet_search_reveals_filtered_evidence_by_packet_identity() {
    let mut app = App::new_for_test();
    app.inject_packet(packet(1));
    let mut second = packet(2);
    second.src = "203.0.113.55".into();
    app.inject_packet(second);
    app.filter.input = "192.0.2.10".into();
    app.rebuild_filtered();
    assert_eq!(app.filtered.len(), 1);
    app.open_search();
    app.search_query = "203.0.113.55".into();
    app.run_search();
    app.search_selected = app
        .search_results
        .iter()
        .position(|result| result.packet_no == Some(2))
        .unwrap();
    app.search_jump();
    assert_eq!(app.selected_packet().unwrap().no, 2);
}

// ─── Global search palette ────────────────────────────────────────────────────

#[tokio::test]
async fn question_mark_opens_search() {
    let mut app = App::new_for_test();
    event::handle(&mut app, key(KeyCode::Char('?')));
    assert!(app.search_open);
}

#[tokio::test]
async fn ctrl_p_opens_command_palette() {
    let mut app = App::new_for_test();
    event::handle(&mut app, ctrl('p'));
    assert!(app.search_open);
}

#[tokio::test]
async fn search_esc_closes_palette() {
    let mut app = App::new_for_test();
    app.search_open = true;
    event::handle(&mut app, key(KeyCode::Esc));
    assert!(!app.search_open);
}

#[tokio::test]
async fn search_query_accumulates() {
    let mut app = App::new_for_test();
    app.search_open = true;
    event::handle(&mut app, key(KeyCode::Char('d')));
    event::handle(&mut app, key(KeyCode::Char('n')));
    event::handle(&mut app, key(KeyCode::Char('s')));
    assert_eq!(app.search_query, "dns");
}

#[tokio::test]
async fn search_backspace_removes_char() {
    let mut app = App::new_for_test();
    app.search_open = true;
    app.search_query = "dns".to_string();
    event::handle(&mut app, key(KeyCode::Backspace));
    assert_eq!(app.search_query, "dn");
}
