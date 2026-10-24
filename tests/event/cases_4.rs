use super::*;

#[tokio::test]
async fn notebook_search_esc_clears_and_exits() {
    let mut app = nb_app();
    app.notebook_searching = true;
    app.notebook_search = "something".to_string();
    event::handle(&mut app, key(KeyCode::Esc));
    assert!(!app.notebook_searching);
    assert!(app.notebook_search.is_empty());
}

#[tokio::test]
async fn notebook_search_enter_exits_search_keeps_query() {
    let mut app = nb_app();
    app.notebook_searching = true;
    app.notebook_search = "c2".to_string();
    event::handle(&mut app, key(KeyCode::Enter));
    assert!(!app.notebook_searching);
    // query preserved for continued filtering
    assert_eq!(app.notebook_search, "c2");
}

#[tokio::test]
async fn notebook_scroll_j_increments() {
    let mut app = nb_app();
    // Add two notes so scroll can go up
    app.notebook.add("Note A", None);
    app.notebook.add("Note B", None);
    app.notebook_scroll = 0;
    event::handle(&mut app, key(KeyCode::Char('j')));
    assert_eq!(app.notebook_scroll, 1);
}

#[tokio::test]
async fn notebook_scroll_k_decrements() {
    let mut app = nb_app();
    app.notebook.add("Note A", None);
    app.notebook.add("Note B", None);
    app.notebook_scroll = 1;
    event::handle(&mut app, key(KeyCode::Char('k')));
    assert_eq!(app.notebook_scroll, 0);
}

#[tokio::test]
async fn notebook_scroll_k_clamps_at_zero() {
    let mut app = nb_app();
    app.notebook_scroll = 0;
    event::handle(&mut app, key(KeyCode::Char('k')));
    assert_eq!(app.notebook_scroll, 0);
}

#[tokio::test]
async fn notebook_g_jumps_to_top() {
    let mut app = nb_app();
    app.notebook_scroll = 10;
    event::handle(&mut app, key(KeyCode::Char('g')));
    assert_eq!(app.notebook_scroll, 0);
}

#[tokio::test]
async fn notebook_delete_removes_note_at_cursor() {
    let mut app = nb_app();
    let id1 = app.notebook.add("First", None);
    app.notebook.add("Second", None);
    app.notebook_scroll = 0;
    // Delete first note
    event::handle(&mut app, key(KeyCode::Char('d')));
    assert_eq!(app.notebook.len(), 1);
    assert_ne!(app.notebook.all()[0].id, id1);
}

#[tokio::test]
async fn hosts_slash_enters_search() {
    let mut app = hosts_app();
    event::handle(&mut app, key(KeyCode::Char('/')));
    assert!(app.hosts_searching);
}

#[tokio::test]
async fn hosts_search_chars_accumulate() {
    let mut app = hosts_app();
    app.hosts_searching = true;
    event::handle(&mut app, key(KeyCode::Char('1')));
    event::handle(&mut app, key(KeyCode::Char('9')));
    event::handle(&mut app, key(KeyCode::Char('2')));
    assert_eq!(app.hosts_search, "192");
}

#[tokio::test]
async fn hosts_search_esc_exits() {
    let mut app = hosts_app();
    app.hosts_searching = true;
    app.hosts_search = "10.0".to_string();
    event::handle(&mut app, key(KeyCode::Esc));
    assert!(!app.hosts_searching);
}

#[tokio::test]
async fn hosts_t_enters_tag_mode() {
    let mut app = hosts_app();
    event::handle(&mut app, key(KeyCode::Char('t')));
    assert!(app.hosts_tagging);
}

#[tokio::test]
async fn hosts_tag_esc_cancels() {
    let mut app = hosts_app();
    app.hosts_tagging = true;
    app.hosts_tag_input = "ioc".to_string();
    event::handle(&mut app, key(KeyCode::Esc));
    assert!(!app.hosts_tagging);
    assert!(app.hosts_tag_input.is_empty());
}

#[rstest]
#[case(KeyCode::Char('a'), "Alerts")]
#[case(KeyCode::Char('e'), "Ids")]
#[case(KeyCode::Char('c'), "Credentials")]
#[case(KeyCode::Char('o'), "OsFingerprint")]
#[case(KeyCode::Char('w'), "ArpWatch")]
#[case(KeyCode::Char('d'), "DnsTunnel")]
#[case(KeyCode::Char('u'), "HttpAnalytics")]
#[case(KeyCode::Char('t'), "TlsWeakness")]
#[case(KeyCode::Char('b'), "BruteForce")]
#[case(KeyCode::Char('v'), "VulnHits")]
#[case(KeyCode::Char('i'), "IocHits")]
#[case(KeyCode::Char('p'), "Replay")]
#[tokio::test]
async fn security_subtab_keys(#[case] code: KeyCode, #[case] expected_name: &str) {
    let mut app = sec_app();
    event::handle(&mut app, key(code));
    let got = format!("{:?}", app.security_tab);
    assert_eq!(
        got, expected_name,
        "expected security subtab {expected_name}"
    );
}

#[tokio::test]
async fn security_scroll_j_increments() {
    let mut app = sec_app();
    app.security_tab = SecuritySubTab::Ids;
    app.security_scroll = 0;
    event::handle(&mut app, key(KeyCode::Char('j')));
    assert_eq!(app.security_scroll, 1);
}

#[tokio::test]
async fn security_scroll_k_decrements() {
    let mut app = sec_app();
    app.security_tab = SecuritySubTab::Ids;
    app.security_scroll = 5;
    event::handle(&mut app, key(KeyCode::Char('k')));
    assert_eq!(app.security_scroll, 4);
}

#[tokio::test]
async fn security_g_jumps_to_top() {
    let mut app = sec_app();
    app.security_tab = SecuritySubTab::Ids;
    app.security_scroll = 100;
    event::handle(&mut app, key(KeyCode::Char('g')));
    assert_eq!(app.security_scroll, 0);
}

#[tokio::test]
async fn alert_center_collects_findings_and_tracks_review_state() {
    let mut app = sec_app();
    app.inject_packet(critical_packet());
    assert!(!app.core.read().unwrap().alert_center.items.is_empty());
    assert_eq!(app.core.read().unwrap().alert_center.items[0].source, "IDS");

    app.alert_overlay_open = false;
    event::handle(&mut app, key(KeyCode::Enter));
    assert_eq!(
        app.core
            .read()
            .unwrap()
            .alert_center
            .selected_item()
            .unwrap()
            .disposition,
        packrat_tui::analysis::alert_center::AlertDisposition::Reviewing,
    );
    event::handle(&mut app, key(KeyCode::Char('C')));
    assert_eq!(
        app.core
            .read()
            .unwrap()
            .alert_center
            .selected_item()
            .unwrap()
            .disposition,
        packrat_tui::analysis::alert_center::AlertDisposition::Confirmed,
    );
}

#[tokio::test]
async fn alert_center_filter_and_navigation_are_bounded() {
    let mut app = sec_app();
    app.configure_core(|core| {
        core.alert_center.record(1, "IDS", "LOW", "low", "detail");
        core.alert_center
            .record(2, "RULE", "CRITICAL", "critical", "detail");
    });
    event::handle(&mut app, key(KeyCode::Char('f')));
    assert_eq!(
        app.core
            .read()
            .unwrap()
            .alert_center
            .selected_item()
            .unwrap()
            .packet_no,
        2
    );
    event::handle(&mut app, key(KeyCode::Char('j')));
    assert_eq!(app.core.read().unwrap().alert_center.selected, 0);
}

#[test]
fn investigation_tray_accepts_typed_context_without_duplicate_items() {
    use packrat_tui::app::{InvestigationItem, InvestigationTray};

    let mut tray = InvestigationTray::default();
    assert!(tray.add(InvestigationItem::Host("192.0.2.10".into())));
    assert!(tray.add(InvestigationItem::Stream("tcp:1".into())));
    assert!(tray.add(InvestigationItem::Alert(7)));
    assert!(tray.add(InvestigationItem::Object(3)));
    assert!(tray.add(InvestigationItem::GraphNode("host:192.0.2.10".into())));
    assert!(tray.add(InvestigationItem::Note(4)));
    assert!(!tray.add(InvestigationItem::Alert(7)));
    assert_eq!(tray.items.len(), 6);
    assert_eq!(tray.active, Some(2));
}

#[tokio::test]
async fn alert_center_m_pins_selected_alert_to_investigation_tray() {
    let mut app = sec_app();
    app.configure_core(|core| {
        core.alert_center
            .record(9, "IDS", "HIGH", "Probe", "detail");
    });
    event::handle(&mut app, key(KeyCode::Char('m')));
    assert_eq!(
        app.worklist.items,
        vec![packrat_tui::app::InvestigationItem::Alert(1)]
    );
}

#[tokio::test]
async fn global_shift_m_pins_host_and_note_contexts() {
    let mut app = App::new_for_test();
    app.inject_packet(packet(1));
    app.active_tab = Tab::Hosts;
    event::handle(&mut app, shift('M'));
    assert!(matches!(
        app.worklist.items[0],
        packrat_tui::app::InvestigationItem::Host(_)
    ));

    app.notebook.add("investigate", None);
    app.active_tab = Tab::Notebook;
    event::handle(&mut app, shift('M'));
    assert_eq!(
        app.worklist.items[1],
        packrat_tui::app::InvestigationItem::Note(1)
    );
}

#[test]
fn investigation_context_resolves_alert_and_handles_expired_source() {
    use packrat_tui::app::InvestigationItem;

    let mut app = App::new_for_test();
    app.configure_core(|core| {
        core.alert_center
            .record(9, "IDS", "HIGH", "Probe", "detector reason");
    });
    app.worklist.add(InvestigationItem::Alert(1));
    let context = app.active_investigation_context().unwrap();
    assert!(context.available);
    assert_eq!(context.kind, "Alert");
    assert!(
        context
            .details
            .iter()
            .any(|(label, value)| label == "Reason" && value == "detector reason")
    );

    app.configure_core(|core| core.alert_center.clear());
    let expired = app.active_investigation_context().unwrap();
    assert!(!expired.available);
    assert!(expired.details[0].1.contains("no longer retained"));
}

// ─── Diff tab ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn diff_b_snapshots_baseline() {
    let mut app = App::new_for_test();
    // inject_packet bypasses the `capturing` guard, adding directly
    use packrat_tui::net::packet::Packet;
    let p = Packet {
        capture: None,
        no: 1,
        timestamp: 0.0,
        src: "1.0.0.1".into(),
        dst: "2.0.0.2".into(),
        protocol: "TCP".into(),
        length: 60,
        info: "".into(),
        src_port: None,
        dst_port: None,
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes: vec![0u8; 60],
    };
    app.inject_packet(p);
    assert_eq!(app.packets.len(), 1);
    // Press B from any tab to snapshot baseline
    event::handle(&mut app, shift('B'));
    assert!(!app.diff_baseline.is_empty());
}
