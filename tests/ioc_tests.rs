//! Tests for the IOC (Indicator of Compromise) matching engine.

use packrat_tui::analysis::ioc::{Ioc, IocEngine, IocKind};
use packrat_tui::net::packet::Packet;

fn make_pkt(no: u64, src: &str, dst: &str, proto: &str, info: &str) -> Packet {
    Packet {
        no,
        timestamp: no as f64,
        src: src.into(),
        dst: dst.into(),
        protocol: proto.into(),
        length: 100,
        info: info.into(),
        src_port: None,
        dst_port: None,
        vlan_id: None,
        bytes: vec![],
    }
}

fn make_ioc(kind: IocKind, value: &str) -> Ioc {
    Ioc {
        kind,
        value: value.into(),
        description: "test IOC".into(),
        source: "test".into(),
    }
}

// ── Load IOC ──────────────────────────────────────────────────────────────────

#[test]
fn load_ip_ioc() {
    let mut engine = IocEngine::default();
    engine.load_ioc(make_ioc(IocKind::Ip, "203.0.113.7"));
    // No hits yet — just loading
    assert!(engine.hits.is_empty());
}

#[test]
fn load_domain_ioc() {
    let mut engine = IocEngine::default();
    engine.load_ioc(make_ioc(IocKind::Domain, "evil-tunnel.com"));
    assert!(engine.hits.is_empty());
}

// ── Check packet ──────────────────────────────────────────────────────────────

#[test]
fn check_packet_src_ip_match() {
    let mut engine = IocEngine::default();
    engine.load_ioc(make_ioc(IocKind::Ip, "203.0.113.7"));
    let pkt = make_pkt(1, "203.0.113.7", "192.168.1.50", "TCP", "beacon");
    engine.check_packet(&pkt);
    let hits = &engine.hits;
    assert!(!hits.is_empty());
    assert_eq!(hits[0].ioc.value, "203.0.113.7");
}

#[test]
fn check_packet_dst_ip_match() {
    let mut engine = IocEngine::default();
    engine.load_ioc(make_ioc(IocKind::Ip, "203.0.113.7"));
    let pkt = make_pkt(2, "192.168.1.50", "203.0.113.7", "TCP", "beacon");
    engine.check_packet(&pkt);
    let hits = &engine.hits;
    assert!(!hits.is_empty());
}

#[test]
fn check_packet_no_match() {
    let mut engine = IocEngine::default();
    engine.load_ioc(make_ioc(IocKind::Ip, "203.0.113.7"));
    let pkt = make_pkt(3, "192.168.1.1", "192.168.1.50", "ARP", "who has");
    engine.check_packet(&pkt);
    assert!(engine.hits.is_empty());
}

#[test]
fn check_packet_domain_in_info() {
    let mut engine = IocEngine::default();
    engine.load_ioc(make_ioc(IocKind::Domain, "evil-tunnel.com"));
    let pkt = make_pkt(4, "192.168.1.50", "8.8.8.8", "DNS",
                       "Query A xyz.evil-tunnel.com");
    engine.check_packet(&pkt);
    let hits = &engine.hits;
    assert!(!hits.is_empty());
    assert_eq!(hits[0].ioc.value, "evil-tunnel.com");
}

#[test]
fn check_packet_domain_no_match() {
    let mut engine = IocEngine::default();
    engine.load_ioc(make_ioc(IocKind::Domain, "evil-tunnel.com"));
    let pkt = make_pkt(5, "192.168.1.50", "8.8.8.8", "DNS",
                       "Query A google.com");
    engine.check_packet(&pkt);
    assert!(engine.hits.is_empty());
}

// ── Multiple IOCs ─────────────────────────────────────────────────────────────

#[test]
fn multiple_iocs_only_matching_fire() {
    let mut engine = IocEngine::default();
    engine.load_ioc(make_ioc(IocKind::Ip, "203.0.113.7"));
    engine.load_ioc(make_ioc(IocKind::Ip, "198.51.100.99"));
    // Only 203.0.113.7 appears in packet
    let pkt = make_pkt(6, "192.168.1.50", "203.0.113.7", "TCP", "");
    engine.check_packet(&pkt);
    assert_eq!(engine.hits.len(), 1);
    assert_eq!(engine.hits[0].ioc.value, "203.0.113.7");
}

#[test]
fn same_ip_multiple_packets_accumulates_hits() {
    let mut engine = IocEngine::default();
    engine.load_ioc(make_ioc(IocKind::Ip, "203.0.113.7"));
    for i in 1..=5u64 {
        let pkt = make_pkt(i, "192.168.1.50", "203.0.113.7", "TCP", "beacon");
        engine.check_packet(&pkt);
    }
    assert_eq!(engine.hits.len(), 5);
}

// ── Hit fields ────────────────────────────────────────────────────────────────

#[test]
fn hit_records_packet_number() {
    let mut engine = IocEngine::default();
    engine.load_ioc(make_ioc(IocKind::Ip, "203.0.113.7"));
    let pkt = make_pkt(42, "192.168.1.50", "203.0.113.7", "TCP", "");
    engine.check_packet(&pkt);
    assert_eq!(engine.hits[0].pkt_no, 42);
}

#[test]
fn hit_records_timestamp() {
    let mut engine = IocEngine::default();
    engine.load_ioc(make_ioc(IocKind::Ip, "10.10.10.10"));
    let mut pkt = make_pkt(1, "192.168.1.50", "10.10.10.10", "TCP", "");
    pkt.timestamp = 1234.5;
    engine.check_packet(&pkt);
    assert!((engine.hits[0].ts - 1234.5).abs() < 0.001);
}
