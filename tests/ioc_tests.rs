//! Tests for the IOC (Indicator of Compromise) matching engine.

use packrat_tui::analysis::ioc::{Ioc, IocEngine, IocKind};
use packrat_tui::net::packet::Packet;

fn make_pkt(no: u64, src: &str, dst: &str, proto: &str, info: &str) -> Packet {
    Packet { capture: None,
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
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
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

fn dns_message(labels: &[&str], response: bool) -> Vec<u8> {
    let mut message = vec![0; 12];
    if response { message[2] = 0x80; }
    message[5] = 1;
    for label in labels {
        message.push(label.len() as u8);
        message.extend(label.as_bytes());
    }
    message.extend([0, 0, 1, 0, 1]);
    message
}

fn dns_packet(no: u64, labels: &[&str], response: bool, tcp: bool) -> Packet {
    let message = dns_message(labels, response);
    let transport = if tcp { 20 } else { 8 };
    let mut bytes = vec![0; 34 + transport];
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    let payload_len = message.len() + usize::from(tcp) * 2;
    bytes[16..18].copy_from_slice(&((20 + transport + payload_len) as u16).to_be_bytes());
    bytes[22] = 64;
    bytes[23] = if tcp { 6 } else { 17 };
    bytes[26..34].copy_from_slice(&[192, 0, 2, 10, 192, 0, 2, 20]);
    bytes[34..36].copy_from_slice(&40_000_u16.to_be_bytes());
    bytes[36..38].copy_from_slice(&53_u16.to_be_bytes());
    if tcp {
        bytes[46] = 0x50;
        bytes[47] = 0x18;
        bytes.extend((message.len() as u16).to_be_bytes());
    } else {
        bytes[38..40].copy_from_slice(&((8 + payload_len) as u16).to_be_bytes());
    }
    bytes.extend(message);
    packrat_tui::net::parser::parse_ethernet(&bytes, no, no as f64)
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
fn check_packet_domain_matches_a_wire_question() {
    let mut engine = IocEngine::default();
    engine.load_ioc(make_ioc(IocKind::Domain, "evil-tunnel.com"));
    let mut pkt = dns_packet(4, &["xyz", "evil-tunnel", "com"], false, false);
    pkt.info.clear();
    engine.check_packet(&pkt);
    let hits = &engine.hits;
    assert!(!hits.is_empty());
    assert_eq!(hits[0].ioc.value, "evil-tunnel.com");
}

#[test]
fn check_packet_domain_no_match_without_a_supported_wire_question() {
    let mut engine = IocEngine::default();
    engine.load_ioc(make_ioc(IocKind::Domain, "evil-tunnel.com"));
    let mut lookalike = dns_packet(5, &["notevil-tunnel", "com"], false, false);
    lookalike.info = "Query A notevil-tunnel.com".into();
    let mut reply = dns_packet(6, &["evil-tunnel", "com"], true, false);
    reply.info = "Response A evil-tunnel.com".into();
    let mut truncated = dns_packet(7, &["evil-tunnel", "com"], false, false);
    truncated.bytes.pop();
    let forged = make_pkt(8, "192.0.2.10", "192.0.2.20", "DNS", "Query A evil-tunnel.com");
    let embedded_dot = dns_packet(9, &["prefix.evil-tunnel", "com"], false, false);
    for packet in [lookalike, reply, truncated, forged, embedded_dot] {
        engine.check_packet(&packet);
    }
    assert!(engine.hits.is_empty());
}

#[test]
fn domain_matches_choose_the_most_specific_indicator_from_tcp_and_udp() {
    let mut engine = IocEngine::default();
    engine.load_ioc(make_ioc(IocKind::Domain, "example.test"));
    engine.load_ioc(make_ioc(IocKind::Domain, "Child.Example.Test."));
    engine.check_packet(&dns_packet(1, &["CHILD", "example", "test"], false, true));
    engine.check_packet(&dns_packet(2, &["deep", "child", "example", "test"], false, false));
    assert_eq!(engine.hits.len(), 2);
    assert_eq!(engine.hits[0].context, "dns_query");
    assert_eq!(engine.hits[1].context, "dns_subdomain");
    assert!(engine.hits.iter().all(|hit| hit.ioc.value == "Child.Example.Test." && hit.ioc.source == "test"));
}

#[test]
fn domain_indicator_alert_points_to_the_wire_question_frame() {
    let mut core = packrat_tui::engine::AnalysisCore::default();
    core.ioc_engine.load_ioc(make_ioc(IocKind::Domain, "indicator.test"));
    let mut lookalike = dns_packet(1, &["notindicator", "test"], false, false);
    lookalike.info = "Query A indicator.test".into();
    core.analyze(&lookalike);
    let mut matched = dns_packet(2, &["cdn", "indicator", "test"], false, false);
    matched.info.clear();
    core.analyze(&matched);
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|item| item.source == "IOC").collect();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].title, "Domain match");
    assert_eq!(alerts[0].packet_no, 2);
    assert_eq!(alerts[0].packet_refs, [2]);
}

#[test]
fn full_indicator_history_does_not_drop_new_ip_or_domain_alerts() {
    let mut core = packrat_tui::engine::AnalysisCore::default();
    core.ioc_engine.load_ioc(make_ioc(IocKind::Ip, "203.0.113.7"));
    core.ioc_engine.load_ioc(make_ioc(IocKind::Ip, "192.0.2.20"));
    core.ioc_engine.load_ioc(make_ioc(IocKind::Domain, "indicator.test"));
    for no in 1..=1000 {
        core.analyze(&make_pkt(no, "203.0.113.7", "192.0.2.30", "TCP", ""));
    }
    assert_eq!(core.ioc_engine.hit_count(), 1000);
    core.analyze(&dns_packet(1001, &["indicator", "test"], false, false));

    let new: Vec<_> = core.alert_center.items.iter()
        .filter(|alert| alert.source == "IOC" && alert.packet_no == 1001)
        .collect();
    assert_eq!(new.len(), 2);
    assert!(new.iter().any(|alert| alert.title == "IP match"));
    assert!(new.iter().any(|alert| alert.title == "Domain match"));
    assert!(new.iter().all(|alert| alert.packet_refs == [1001]));
    assert_eq!(core.ioc_engine.hit_count(), 1000);
    assert_eq!(core.ioc_engine.hits[0].pkt_no, 3);
    assert_eq!(core.ioc_engine.hits[998].pkt_no, 1001);
    assert_eq!(core.ioc_engine.hits[999].pkt_no, 1001);
    assert_eq!(core.ioc_engine.evicted_hit_count(), 2);
    core.clear();
    assert_eq!(core.ioc_engine.hit_count(), 0);
    assert_eq!(core.ioc_engine.evicted_hit_count(), 0);
    assert_eq!(core.ioc_engine.ioc_count(), 3);
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
