#[path = "support/http3.rs"]
mod support;
use packrat_tui::analysis::quic_scope::QuicScope;

#[test]
fn quic_inventory_evicts_first_seen_connections_without_unbounded_growth() {
    let mut scope = QuicScope::default();
    for number in 1..=1100u32 {
        let mut packet = support::quic_packet(number as u64);
        packet.bytes[48..52].copy_from_slice(&number.to_be_bytes());
        scope.ingest(&packet);
    }
    assert_eq!(scope.connections.len(), 1024);
    assert_eq!(scope.evicted_connections, 76);
    assert!(!scope.connections.contains_key("00000001"));
    assert!(scope.connections.contains_key(&format!("{:08x}", 1100)));
    scope.clear();
    assert_eq!(scope.evicted_connections, 0);
    assert!(scope.connections.is_empty());
}

#[test]
fn address_churn_is_bounded_and_explicitly_marked() {
    let mut scope = QuicScope::default();
    for number in 1..=100 {
        let mut packet = support::quic_packet(number);
        packet.src = format!("192.0.2.{number}");
        scope.ingest(&packet);
    }
    let connection = scope.all()[0];
    assert_eq!(connection.addresses.len(), 32);
    assert!(connection.addresses_truncated);
    assert!(connection.migration_observed());
    assert_eq!(connection.packets, 100);
}
