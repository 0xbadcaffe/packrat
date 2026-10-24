use super::*;

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
            mode: StartupMode::Capture,
            telemetry_listen: None,
            key_log_path: None,
            tls_decrypt_helper_path: None,
            quic_decode_helper_path: None,
            latch_mode: LatchMode::Monitor,
            latch_expiry_seconds: 900,
            protected_addresses: vec![],
            sandbox: false,
            socket_events_path: None,
            latch_helper_path: None,
            reputation_helper_path: None,
            capture_helper_path: None,
            endpoint_evidence_path: None,
            archive_path: None,
        })
    );
}

#[test]
fn parse_startup_args_enables_simulation() {
    assert_eq!(
        app::parse_startup_args(["--simulation"]).unwrap(),
        CliAction::Run(StartupOptions {
            mode: StartupMode::Simulation,
            telemetry_listen: None,
            key_log_path: None,
            tls_decrypt_helper_path: None,
            quic_decode_helper_path: None,
            latch_mode: LatchMode::Monitor,
            latch_expiry_seconds: 900,
            protected_addresses: vec![],
            sandbox: false,
            socket_events_path: None,
            latch_helper_path: None,
            reputation_helper_path: None,
            capture_helper_path: None,
            endpoint_evidence_path: None,
            archive_path: None,
        })
    );
    assert_eq!(
        app::parse_startup_args(["-s"]).unwrap(),
        CliAction::Run(StartupOptions {
            mode: StartupMode::Simulation,
            telemetry_listen: None,
            key_log_path: None,
            tls_decrypt_helper_path: None,
            quic_decode_helper_path: None,
            latch_mode: LatchMode::Monitor,
            latch_expiry_seconds: 900,
            protected_addresses: vec![],
            sandbox: false,
            socket_events_path: None,
            latch_helper_path: None,
            reputation_helper_path: None,
            capture_helper_path: None,
            endpoint_evidence_path: None,
            archive_path: None,
        })
    );
}

#[test]
fn parse_startup_args_rejects_unknown_flags() {
    assert!(app::parse_startup_args(["--real-capture"]).is_err());
}

#[test]
fn endpoint_evidence_cli_requires_a_path_and_is_discoverable() {
    assert!(app::parse_startup_args(["--endpoint-evidence"]).is_err());
    let CliAction::Run(options) =
        app::parse_startup_args(["--endpoint-evidence", "audit.ndjson"]).unwrap()
    else {
        panic!("expected startup options")
    };
    assert_eq!(options.endpoint_evidence_path, Some("audit.ndjson".into()));
    assert!(app::usage().contains("--endpoint-evidence"));
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
            tls_decrypt_helper_path: None,
            quic_decode_helper_path: None,
            latch_mode: LatchMode::Monitor,
            latch_expiry_seconds: 900,
            protected_addresses: vec![],
            sandbox: false,
            socket_events_path: None,
            latch_helper_path: None,
            reputation_helper_path: None,
            capture_helper_path: None,
            endpoint_evidence_path: None,
            archive_path: None,
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
            tls_decrypt_helper_path: None,
            quic_decode_helper_path: None,
            latch_mode: LatchMode::Monitor,
            latch_expiry_seconds: 900,
            protected_addresses: vec![],
            sandbox: false,
            socket_events_path: None,
            latch_helper_path: None,
            reputation_helper_path: None,
            capture_helper_path: None,
            endpoint_evidence_path: None,
            archive_path: None,
        })
    );
}

#[test]
fn parse_startup_args_accepts_tls_decrypt_helper_path() {
    let CliAction::Run(options) =
        app::parse_startup_args(["--tls-decrypt-helper", "/usr/libexec/packrat-tls-decrypt"])
            .unwrap()
    else {
        panic!("expected run options");
    };
    assert_eq!(
        options.tls_decrypt_helper_path,
        Some("/usr/libexec/packrat-tls-decrypt".into())
    );
}

#[test]
fn parse_startup_args_accepts_quic_decode_helper_path() {
    let CliAction::Run(options) =
        app::parse_startup_args(["--quic-decode-helper", "/usr/libexec/packrat-quic-decode"])
            .unwrap()
    else {
        panic!("expected run options");
    };
    assert_eq!(
        options.quic_decode_helper_path,
        Some("/usr/libexec/packrat-quic-decode".into())
    );
}

#[test]
fn parse_startup_args_accepts_socket_events_path() {
    let CliAction::Run(options) =
        app::parse_startup_args(["--socket-events", "/tmp/sockets.csv"]).unwrap()
    else {
        panic!("expected run options");
    };
    assert_eq!(options.socket_events_path, Some("/tmp/sockets.csv".into()));
}

#[test]
fn parse_startup_args_accepts_latch_helper_path() {
    let CliAction::Run(options) =
        app::parse_startup_args(["--latch-helper", "/usr/libexec/packrat-latch"]).unwrap()
    else {
        panic!("expected run options");
    };
    assert_eq!(
        options.latch_helper_path,
        Some("/usr/libexec/packrat-latch".into())
    );
}

#[test]
fn parse_startup_args_accepts_reputation_helper_path() {
    let CliAction::Run(options) =
        app::parse_startup_args(["--reputation-helper", "/usr/libexec/packrat-reputation"])
            .unwrap()
    else {
        panic!("expected run options");
    };
    assert_eq!(
        options.reputation_helper_path,
        Some("/usr/libexec/packrat-reputation".into())
    );
}

#[test]
fn parse_startup_args_accepts_capture_helper_path() {
    let CliAction::Run(options) =
        app::parse_startup_args(["--capture-helper", "/usr/libexec/packrat-capture-helper"])
            .unwrap()
    else {
        panic!("expected run options");
    };
    assert_eq!(
        options.capture_helper_path,
        Some("/usr/libexec/packrat-capture-helper".into())
    );
}

#[test]
fn parse_startup_args_configures_traffic_latch_safely() {
    let result = app::parse_startup_args([
        "--traffic-latch",
        "auto",
        "--latch-seconds",
        "60",
        "--protect-address",
        "192.0.2.1",
    ])
    .unwrap();
    let CliAction::Run(options) = result else {
        panic!("expected run options");
    };
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

#[tokio::test]
async fn critical_detection_requires_review_and_retains_evidence_after_acknowledgement() {
    let mut app = App::new_for_test();
    app.inject_packet(critical_packet());
    assert!(app.alert_overlay_open);
    assert_eq!(app.core.read().unwrap().incidents.incidents.len(), 1);

    event::handle(&mut app, key(KeyCode::Enter));
    assert_eq!(app.active_tab, Tab::Analysis);
    assert_eq!(app.analysis_section, app::INCIDENT_ANALYSIS_SECTION);
    assert!(!app.alert_overlay_open);

    event::handle(&mut app, key(KeyCode::Char('C')));
    assert!(app.core.read().unwrap().incidents.active().is_none());
    assert_eq!(
        app.core.read().unwrap().incidents.incidents[0]
            .packet_history
            .len(),
        1
    );
}

#[tokio::test]
async fn automatic_latch_requires_policy_gate_for_default_critical_signal() {
    let mut app = App::new_for_test();
    app.traffic_latch.mode = LatchMode::Automatic;
    app.selected_iface = "test-live".into();
    app.capturing = true;
    app.ingest_packet(live_critical_packet());

    assert_eq!(app.traffic_latch.actions.len(), 1);
    assert_eq!(
        app.traffic_latch.actions[0].status,
        LatchStatus::PendingApproval
    );
    assert!(
        app.traffic_latch.actions[0]
            .detail
            .contains("automatic gate not satisfied")
    );
}

#[test]
fn injected_and_simulated_packets_cannot_request_or_approve_live_containment() {
    for simulated_capture in [false, true] {
        let mut app = App::new_for_test();
        app.traffic_latch.mode = LatchMode::Automatic;
        app.latch_helper_path = Some("/must-not-run-a-firewall-helper".into());
        if simulated_capture {
            app.capturing = true;
            app.ingest_packet(critical_packet());
        } else {
            app.inject_packet(critical_packet());
        }
        assert_eq!(app.traffic_latch.actions[0].status, LatchStatus::Observed);
        app.approve_active_latch();
        assert_eq!(app.traffic_latch.actions[0].status, LatchStatus::Observed);
        assert!(
            app.status_msg
                .as_ref()
                .unwrap()
                .contains("Containment disabled")
        );
    }
}
