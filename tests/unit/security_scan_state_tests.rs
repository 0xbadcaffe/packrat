use super::*;
use crate::net::parser::parse_ethernet;

#[test]
fn unique_probe_and_latch_state_are_bounded_within_one_scan_window() {
    let mut engine = SecurityEngine::default();
    let mut packet = parse_ethernet(&[], 1, 1.0);
    packet.src = "192.0.2.1".into();
    for host in 1..=100 {
        packet.dst = format!("198.51.100.{host}");
        for port in 1..=SCAN_UNIQUE_THRESHOLD as u16 {
            engine.record_scan_probe(&packet, port, "TCP");
            packet.no += 1;
            packet.timestamp += 0.001;
        }
    }
    let state = engine.scan_sources.get(&scan_key(&packet, "TCP")).unwrap();
    assert_eq!(state.probes.len(), MAX_SCAN_PROBES_PER_SOURCE);
    assert!(state.vertical_alerted.len() <= state.probes.len());
    assert!(state.horizontal_alerted.len() <= state.probes.len());
    assert!(state.vertical_alerted.contains("198.51.100.100"));
    assert!(!state.vertical_alerted.contains("198.51.100.1"));
}
