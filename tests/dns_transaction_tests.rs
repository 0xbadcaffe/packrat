use packrat_tui::analysis::dns_transactions::{DnsFindingKind, DnsTransactionTracker};
use packrat_tui::net::packet::Packet;
use packrat_tui::net::security::SecurityEngine;

fn dns_packet(
    no: u64,
    response: bool,
    source: &str,
    destination: &str,
    id: u16,
    name: &str,
) -> Packet {
    let mut dns = Vec::new();
    dns.extend_from_slice(&id.to_be_bytes());
    dns.extend_from_slice(&if response { 0x8180_u16 } else { 0x0100_u16 }.to_be_bytes());
    dns.extend_from_slice(&1_u16.to_be_bytes());
    dns.extend_from_slice(&0_u16.to_be_bytes());
    dns.extend_from_slice(&0_u16.to_be_bytes());
    dns.extend_from_slice(&0_u16.to_be_bytes());
    for label in name.split('.') {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.push(0);
    dns.extend_from_slice(&1_u16.to_be_bytes());
    dns.extend_from_slice(&1_u16.to_be_bytes());

    let mut bytes = vec![0_u8; 14 + 20 + 8];
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&((20 + 8 + dns.len()) as u16).to_be_bytes());
    bytes[23] = 17;
    let (source_port, destination_port): (u16, u16) =
        if response { (53, 40_000) } else { (40_000, 53) };
    bytes[34..36].copy_from_slice(&source_port.to_be_bytes());
    bytes[36..38].copy_from_slice(&destination_port.to_be_bytes());
    bytes[38..40].copy_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
    bytes.extend_from_slice(&dns);
    Packet {
        no,
        timestamp: no as f64,
        src: source.into(),
        dst: destination.into(),
        protocol: "DNS".into(),
        length: bytes.len() as u16,
        info: name.into(),
        src_port: Some(source_port),
        dst_port: Some(destination_port),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes,
    }
}

fn dns_ipv6_packet(
    no: u64,
    response: bool,
    source: &str,
    destination: &str,
    id: u16,
    name: &str,
) -> Packet {
    let ipv4 = dns_packet(no, response, source, destination, id, name);
    let dns = &ipv4.bytes[42..];
    let mut bytes = vec![0_u8; 14 + 40 + 8];
    bytes[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
    bytes[14] = 0x60;
    bytes[18..20].copy_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
    bytes[20] = 17;
    let (source_port, destination_port): (u16, u16) =
        if response { (53, 40_000) } else { (40_000, 53) };
    bytes[54..56].copy_from_slice(&source_port.to_be_bytes());
    bytes[56..58].copy_from_slice(&destination_port.to_be_bytes());
    bytes[58..60].copy_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
    bytes.extend_from_slice(dns);
    Packet {
        bytes,
        length: (14 + 40 + 8 + dns.len()) as u16,
        src_port: Some(source_port),
        dst_port: Some(destination_port),
        ..ipv4
    }
}

#[test]
fn correlates_matching_transactions_and_rejects_question_substitution() {
    let mut tracker = DnsTransactionTracker::default();
    let query = dns_packet(1, false, "10.0.0.5", "10.0.0.53", 0x1234, "safe.example");
    assert!(tracker.observe(&query).is_empty());
    let reply = dns_packet(2, true, "10.0.0.53", "10.0.0.5", 0x1234, "safe.example");
    assert!(tracker.observe(&reply).is_empty());

    let query = dns_packet(3, false, "10.0.0.5", "10.0.0.53", 0x5678, "safe.example");
    tracker.observe(&query);
    let forged = dns_packet(4, true, "10.0.0.53", "10.0.0.5", 0x5678, "evil.example");
    assert_eq!(
        tracker.observe(&forged)[0].kind,
        DnsFindingKind::QuestionMismatch
    );
}

#[test]
fn detects_unsolicited_unexpected_and_competing_responses() {
    let mut tracker = DnsTransactionTracker::default();
    let unsolicited = dns_packet(1, true, "10.0.0.99", "10.0.0.5", 7, "safe.example");
    assert_eq!(
        tracker.observe(&unsolicited)[0].kind,
        DnsFindingKind::UnsolicitedResponse
    );

    let query = dns_packet(2, false, "10.0.0.5", "10.0.0.53", 8, "safe.example");
    tracker.observe(&query);
    let rogue = dns_packet(3, true, "10.0.0.99", "10.0.0.5", 8, "safe.example");
    assert_eq!(
        tracker.observe(&rogue)[0].kind,
        DnsFindingKind::UnexpectedResponder
    );
    let expected = dns_packet(4, true, "10.0.0.53", "10.0.0.5", 8, "safe.example");
    assert_eq!(
        tracker.observe(&expected)[0].kind,
        DnsFindingKind::ConflictingResponse
    );
}

#[test]
fn security_engine_emits_dns_integrity_alert() {
    let mut engine = SecurityEngine::default();
    engine.update(&dns_packet(
        1,
        false,
        "10.0.0.5",
        "10.0.0.53",
        9,
        "safe.example",
    ));
    engine.update(&dns_packet(
        2,
        true,
        "10.0.0.99",
        "10.0.0.5",
        9,
        "safe.example",
    ));
    assert!(engine
        .ids_alerts
        .iter()
        .any(|alert| alert.signature == "Unexpected DNS responder"));
}

#[test]
fn correlates_ipv6_dns_and_ignores_compression_pointer_loops() {
    let mut tracker = DnsTransactionTracker::default();
    let query = dns_ipv6_packet(1, false, "2001:db8::5", "2001:db8::53", 10, "safe.example");
    let reply = dns_ipv6_packet(2, true, "2001:db8::53", "2001:db8::5", 10, "safe.example");
    assert!(tracker.observe(&query).is_empty());
    assert!(tracker.observe(&reply).is_empty());

    let mut malformed = dns_packet(3, false, "10.0.0.5", "10.0.0.53", 11, "x");
    malformed.bytes[54..56].copy_from_slice(&[0xc0, 0x0c]);
    assert!(tracker.observe(&malformed).is_empty());
}
