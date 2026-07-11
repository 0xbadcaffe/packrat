//! Key-event handler tests.
//!
//! Strategy: construct an App with `new_for_test()` (no real capture, no UI),
//! send synthetic crossterm key events through `event::handle()`, and assert
//! on the resulting App state.
//!
//! Uses `rstest` for parametrized cases that cover every tab-switch key and
//! every important per-tab action key.

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use packrat_tui::app::{self, App, CliAction, StartupMode, StartupOptions};
use packrat_tui::analysis::traffic_latch::{LatchMode, LatchStatus};
use packrat_tui::event;
use packrat_tui::tabs::{Tab, Workspace};
use rstest::rstest;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn key(code: KeyCode) -> Event {
    Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn ctrl(c: char) -> Event {
    Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
}

fn shift(c: char) -> Event {
    Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::SHIFT))
}

#[tokio::test]
async fn app_new_for_test_ok() {
    let app = App::new_for_test();
    // Starts on Packets tab, not capturing
    assert_eq!(app.active_tab, Tab::Packets);
    assert!(!app.capturing);
    assert!(!app.picking_iface);
}

#[test]
fn parse_startup_args_defaults_to_capture() {
    assert_eq!(
        app::parse_startup_args(std::iter::empty::<&str>()).unwrap(),
        CliAction::Run(StartupOptions {
            mode: StartupMode::Capture, telemetry_listen: None, key_log_path: None,
            latch_mode: LatchMode::Monitor, latch_expiry_seconds: 900, protected_addresses: vec![],
            sandbox: false, socket_events_path: None, latch_helper_path: None,
        })
    );
}

#[test]
fn parse_startup_args_enables_simulation() {
    assert_eq!(
        app::parse_startup_args(["--simulation"]).unwrap(),
        CliAction::Run(StartupOptions {
            mode: StartupMode::Simulation, telemetry_listen: None, key_log_path: None,
            latch_mode: LatchMode::Monitor, latch_expiry_seconds: 900, protected_addresses: vec![],
            sandbox: false, socket_events_path: None, latch_helper_path: None,
        })
    );
    assert_eq!(
        app::parse_startup_args(["-s"]).unwrap(),
        CliAction::Run(StartupOptions {
            mode: StartupMode::Simulation, telemetry_listen: None, key_log_path: None,
            latch_mode: LatchMode::Monitor, latch_expiry_seconds: 900, protected_addresses: vec![],
            sandbox: false, socket_events_path: None, latch_helper_path: None,
        })
    );
}

#[test]
fn parse_startup_args_rejects_unknown_flags() {
    assert!(app::parse_startup_args(["--real-capture"]).is_err());
}

#[test]
fn parse_startup_args_accepts_local_telemetry_listener() {
    let result = app::parse_startup_args(["--telemetry-listen", "127.0.0.1:9477"]).unwrap();
    assert_eq!(
        result,
        CliAction::Run(StartupOptions {
            mode: StartupMode::Capture,
            telemetry_listen: Some("127.0.0.1:9477".parse().unwrap()),
            key_log_path: None,
            latch_mode: LatchMode::Monitor,
            latch_expiry_seconds: 900,
            protected_addresses: vec![],
            sandbox: false,
            socket_events_path: None,
            latch_helper_path: None,
        })
    );
}

#[test]
fn parse_startup_args_accepts_key_log_path() {
    let result = app::parse_startup_args(["--key-log", "/tmp/keys.log"]).unwrap();
    assert_eq!(
        result,
        CliAction::Run(StartupOptions {
            mode: StartupMode::Capture,
            telemetry_listen: None,
            key_log_path: Some("/tmp/keys.log".into()),
            latch_mode: LatchMode::Monitor,
            latch_expiry_seconds: 900,
            protected_addresses: vec![],
            sandbox: false,
            socket_events_path: None,
            latch_helper_path: None,
        })
    );
}

#[test]
fn parse_startup_args_accepts_socket_events_path() {
    let CliAction::Run(options) = app::parse_startup_args(["--socket-events", "/tmp/sockets.csv"]).unwrap() else {
        panic!("expected run options");
    };
    assert_eq!(options.socket_events_path, Some("/tmp/sockets.csv".into()));
}

#[test]
fn parse_startup_args_accepts_latch_helper_path() {
    let CliAction::Run(options) = app::parse_startup_args(["--latch-helper", "/usr/libexec/packrat-latch"]).unwrap() else {
        panic!("expected run options");
    };
    assert_eq!(options.latch_helper_path, Some("/usr/libexec/packrat-latch".into()));
}

#[test]
fn parse_startup_args_configures_traffic_latch_safely() {
    let result = app::parse_startup_args([
        "--traffic-latch", "auto", "--latch-seconds", "60",
        "--protect-address", "192.0.2.1",
    ]).unwrap();
    let CliAction::Run(options) = result else { panic!("expected run options"); };
    assert_eq!(options.latch_mode, LatchMode::Automatic);
    assert_eq!(options.latch_expiry_seconds, 60);
    assert_eq!(
        options.protected_addresses,
        vec!["192.0.2.1".parse::<std::net::IpAddr>().unwrap()]
    );
}

#[test]
fn parse_startup_args_enables_landlock_sandbox() {
    let CliAction::Run(options) = app::parse_startup_args(["--sandbox"]).unwrap() else {
        panic!("expected run options");
    };
    assert!(options.sandbox);
}

#[tokio::test]
async fn app_new_defaults_to_real_interface_selection() {
    let (tx, _rx) = tokio::sync::mpsc::channel(1024);
    let app = App::new(tx);
    assert!(app.picking_iface);
    assert!(!app.capturing);
    assert!(!app.iface_list.iter().any(|iface| iface == "simulated"));
}

#[tokio::test]
async fn app_simulation_mode_starts_scenario_capture() {
    let (tx, _rx) = tokio::sync::mpsc::channel(1024);
    let app = App::new_with_mode(tx, StartupMode::Simulation);
    assert!(!app.picking_iface);
    assert!(app.capturing);
    assert_eq!(app.selected_iface, "simulated");
    assert!(!app.packets.is_empty());
}

// ─── Quit keys ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn quit_key_q() {
    let mut app = App::new_for_test();
    let quit = event::handle(&mut app, key(KeyCode::Char('q')));
    assert!(quit, "q should quit");
}

#[tokio::test]
async fn quit_key_ctrl_c() {
    let mut app = App::new_for_test();
    let quit = event::handle(&mut app, ctrl('c'));
    assert!(quit, "Ctrl+C should quit");
}

#[tokio::test]
async fn q_does_not_quit_in_text_mode() {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Notebook;
    // Enter notebook editing mode
    event::handle(&mut app, key(KeyCode::Char('n')));
    assert!(app.notebook_editing);
    // Now 'q' should be a character, not a quit
    let quit = event::handle(&mut app, key(KeyCode::Char('q')));
    assert!(!quit, "q should not quit while in text mode");
    assert_eq!(app.notebook_input, "q");
}

fn critical_packet() -> packrat_tui::net::packet::Packet {
    packrat_tui::net::packet::Packet {
        no: 77,
        timestamp: 12.5,
        src: "203.0.113.7".into(),
        dst: "10.0.0.5".into(),
        protocol: "HTTP".into(),
        length: 128,
        info: "exploit attempt".into(),
        src_port: Some(44444),
        dst_port: Some(8080),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes: b"GET /${jndi:ldap://203.0.113.7/x}".to_vec(),
    }
}

#[tokio::test]
async fn critical_detection_requires_review_and_retains_evidence_after_acknowledgement() {
    let mut app = App::new_for_test();
    app.inject_packet(critical_packet());
    assert!(app.alert_overlay_open);
    assert_eq!(app.incidents.incidents.len(), 1);

    event::handle(&mut app, key(KeyCode::Enter));
    assert_eq!(app.active_tab, Tab::Analysis);
    assert_eq!(app.analysis_section, app::INCIDENT_ANALYSIS_SECTION);
    assert!(!app.alert_overlay_open);

    event::handle(&mut app, key(KeyCode::Char('C')));
    assert!(app.incidents.active().is_none());
    assert_eq!(app.incidents.incidents[0].packet_history.len(), 1);
}

#[tokio::test]
async fn automatic_latch_requires_policy_gate_for_default_critical_signal() {
    let mut app = App::new_for_test();
    app.traffic_latch.mode = LatchMode::Automatic;
    app.inject_packet(critical_packet());

    assert_eq!(app.traffic_latch.actions.len(), 1);
    assert_eq!(app.traffic_latch.actions[0].status, LatchStatus::PendingApproval);
    assert!(app.traffic_latch.actions[0].detail.contains("automatic gate not satisfied"));
}

// ─── Workspace navigation ────────────────────────────────────────────────────

#[rstest]
#[case(KeyCode::Char('1'), Tab::Packets)]
#[case(KeyCode::Char('2'), Tab::Analysis)]
#[case(KeyCode::Char('3'), Tab::Security)]
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
async fn theme_picker_esc_closes() {
    let mut app = App::new_for_test();
    app.theme_picker_open = true;
    event::handle(&mut app, key(KeyCode::Esc));
    assert!(!app.theme_picker_open);
}

#[tokio::test]
async fn theme_picker_j_moves_cursor_down() {
    let mut app = App::new_for_test();
    app.theme_picker_open = true;
    app.theme_picker_cursor = 0;
    event::handle(&mut app, key(KeyCode::Char('j')));
    assert_eq!(app.theme_picker_cursor, 1);
}

#[tokio::test]
async fn theme_picker_k_moves_cursor_up() {
    let mut app = App::new_for_test();
    app.theme_picker_open = true;
    app.theme_picker_cursor = 2;
    event::handle(&mut app, key(KeyCode::Char('k')));
    assert_eq!(app.theme_picker_cursor, 1);
}

#[tokio::test]
async fn theme_picker_k_clamps_at_zero() {
    let mut app = App::new_for_test();
    app.theme_picker_open = true;
    app.theme_picker_cursor = 0;
    event::handle(&mut app, key(KeyCode::Char('k')));
    assert_eq!(app.theme_picker_cursor, 0);
}

#[tokio::test]
async fn shift_p_opens_project_manager() {
    let mut app = App::new_for_test();
    event::handle(&mut app, shift('P'));
    assert!(app.project_manager_open);
}

#[tokio::test]
async fn project_manager_esc_closes() {
    let mut app = App::new_for_test();
    app.project_manager_open = true;
    event::handle(&mut app, key(KeyCode::Esc));
    assert!(!app.project_manager_open);
}

#[tokio::test]
async fn help_key_opens_help() {
    let mut app = App::new_for_test();
    // 'h' opens help from most tabs — use Craft where it's explicitly handled
    app.active_tab = Tab::Craft;
    event::handle(&mut app, key(KeyCode::Char('h')));
    assert!(app.show_help);
}

#[tokio::test]
async fn help_esc_closes_help() {
    let mut app = App::new_for_test();
    app.show_help = true;
    event::handle(&mut app, key(KeyCode::Esc));
    assert!(!app.show_help);
}

#[tokio::test]
async fn help_h_closes_help() {
    let mut app = App::new_for_test();
    app.show_help = true;
    event::handle(&mut app, key(KeyCode::Char('h')));
    assert!(!app.show_help);
}

// ─── Notebook tab ─────────────────────────────────────────────────────────────

fn nb_app() -> App {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Notebook;
    app
}

#[tokio::test]
async fn notebook_n_enters_edit_mode() {
    let mut app = nb_app();
    event::handle(&mut app, key(KeyCode::Char('n')));
    assert!(app.notebook_editing);
}

#[tokio::test]
async fn notebook_edit_chars_go_to_input() {
    let mut app = nb_app();
    app.notebook_editing = true;
    event::handle(&mut app, key(KeyCode::Char('H')));
    event::handle(&mut app, key(KeyCode::Char('i')));
    assert_eq!(app.notebook_input, "Hi");
}

#[tokio::test]
async fn notebook_edit_backspace_deletes_char() {
    let mut app = nb_app();
    app.notebook_editing = true;
    app.notebook_input = "Hello".to_string();
    event::handle(&mut app, key(KeyCode::Backspace));
    assert_eq!(app.notebook_input, "Hell");
}

#[tokio::test]
async fn notebook_edit_enter_saves_note() {
    let mut app = nb_app();
    app.notebook_editing = true;
    app.notebook_input = "My note".to_string();
    event::handle(&mut app, key(KeyCode::Enter));
    assert!(!app.notebook_editing);
    assert!(app.notebook_input.is_empty());
    assert_eq!(app.notebook.len(), 1);
    assert_eq!(app.notebook.all()[0].text, "My note");
}

#[tokio::test]
async fn notebook_edit_enter_empty_does_not_save() {
    let mut app = nb_app();
    app.notebook_editing = true;
    // input is empty
    event::handle(&mut app, key(KeyCode::Enter));
    assert!(!app.notebook_editing);
    assert_eq!(app.notebook.len(), 0);
}

#[tokio::test]
async fn notebook_edit_esc_cancels() {
    let mut app = nb_app();
    app.notebook_editing = true;
    app.notebook_input = "Typed but cancelled".to_string();
    event::handle(&mut app, key(KeyCode::Esc));
    assert!(!app.notebook_editing);
    assert!(app.notebook_input.is_empty());
    assert_eq!(app.notebook.len(), 0);
}

#[tokio::test]
async fn notebook_slash_enters_search() {
    let mut app = nb_app();
    event::handle(&mut app, key(KeyCode::Char('/')));
    assert!(app.notebook_searching);
    assert!(app.notebook_search.is_empty());
}

#[tokio::test]
async fn notebook_search_chars_accumulate() {
    let mut app = nb_app();
    app.notebook_searching = true;
    event::handle(&mut app, key(KeyCode::Char('d')));
    event::handle(&mut app, key(KeyCode::Char('n')));
    event::handle(&mut app, key(KeyCode::Char('s')));
    assert_eq!(app.notebook_search, "dns");
}

#[tokio::test]
async fn notebook_search_backspace() {
    let mut app = nb_app();
    app.notebook_searching = true;
    app.notebook_search = "dnss".to_string();
    event::handle(&mut app, key(KeyCode::Backspace));
    assert_eq!(app.notebook_search, "dns");
}

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

// ─── Hosts tab ────────────────────────────────────────────────────────────────

fn hosts_app() -> App {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Hosts;
    app
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

// ─── Security tab ─────────────────────────────────────────────────────────────

fn sec_app() -> App {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Security;
    app
}

#[rstest]
#[case(KeyCode::Char('a'), "Ids")]
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
    assert_eq!(got, expected_name, "expected security subtab {expected_name}");
}

#[tokio::test]
async fn security_scroll_j_increments() {
    let mut app = sec_app();
    app.security_scroll = 0;
    event::handle(&mut app, key(KeyCode::Char('j')));
    assert_eq!(app.security_scroll, 1);
}

#[tokio::test]
async fn security_scroll_k_decrements() {
    let mut app = sec_app();
    app.security_scroll = 5;
    event::handle(&mut app, key(KeyCode::Char('k')));
    assert_eq!(app.security_scroll, 4);
}

#[tokio::test]
async fn security_g_jumps_to_top() {
    let mut app = sec_app();
    app.security_scroll = 100;
    event::handle(&mut app, key(KeyCode::Char('g')));
    assert_eq!(app.security_scroll, 0);
}

// ─── Diff tab ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn diff_b_snapshots_baseline() {
    let mut app = App::new_for_test();
    // inject_packet bypasses the `capturing` guard, adding directly
    use packrat_tui::net::packet::Packet;
    let p = Packet {
        no: 1, timestamp: 0.0,
        src: "1.0.0.1".into(), dst: "2.0.0.2".into(),
        protocol: "TCP".into(), length: 60, info: "".into(),
        src_port: None, dst_port: None, vlan_id: None,
        vlan_pcp: None, vlan_dei: None, outer_vlan_id: None,
        bytes: vec![0u8; 60],
    };
    app.inject_packet(p);
    assert_eq!(app.packets.len(), 1);
    // Press B from any tab to snapshot baseline
    event::handle(&mut app, shift('B'));
    assert!(!app.diff_baseline.is_empty());
}

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
    app.stream_overlay = Some(("test".to_string(), vec![]));
    event::handle(&mut app, key(code));
    assert!(app.stream_overlay.is_none());
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

// ─── Objects tab ─────────────────────────────────────────────────────────────

fn objects_app() -> App {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Objects;
    app
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
    assert_eq!(Tab::COUNT, 18);
}

// ─── Global search palette ────────────────────────────────────────────────────

#[tokio::test]
async fn question_mark_opens_search() {
    let mut app = App::new_for_test();
    event::handle(&mut app, key(KeyCode::Char('?')));
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
