use packrat_tui::analysis::dns_transactions::{DnsFindingKind, DnsTransactionTracker};
use packrat_tui::engine::AnalysisCore;
use packrat_tui::net::packet::{CaptureMetadata, CaptureTimestamp, Packet, TimestampResolution};
use packrat_tui::net::security::SecurityEngine;
use packrat_tui::net::security::Severity;

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
    Packet { capture: None,
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
    Packet { capture: None,
        bytes,
        length: (14 + 40 + 8 + dns.len()) as u16,
        src_port: Some(source_port),
        dst_port: Some(destination_port),
        ..ipv4
    }
}

fn append_answer(packet: &mut Packet, owner: &[u8], rr_type: u16, ttl: u32, data: &[u8]) {
    let header = 42;
    let count = u16::from_be_bytes(packet.bytes[header + 6..header + 8].try_into().unwrap());
    packet.bytes[header + 6..header + 8].copy_from_slice(&(count + 1).to_be_bytes());
    packet.bytes.extend_from_slice(owner);
    packet.bytes.extend_from_slice(&rr_type.to_be_bytes());
    packet.bytes.extend_from_slice(&1_u16.to_be_bytes());
    packet.bytes.extend_from_slice(&ttl.to_be_bytes());
    packet.bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
    packet.bytes.extend_from_slice(data);
    packet.length = packet.bytes.len() as u16;
    packet.bytes[16..18].copy_from_slice(&(packet.length - 14).to_be_bytes());
    packet.bytes[38..40].copy_from_slice(&(packet.length - 34).to_be_bytes());
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
fn reply_without_observed_query_is_a_visibility_alert_not_an_incident() {
    let mut core = AnalysisCore::default();
    let reply = dns_packet(1, true, "10.0.0.53", "10.0.0.5", 7, "safe.example");
    core.analyze(&reply);
    let alert = core.alert_center.items.iter().find(|a| {
        a.title == "DNS reply without observed query"
    }).expect("missing query visibility alert");
    assert_eq!(alert.severity, "LOW");
    assert_eq!(alert.packet_refs, [1]);
    assert!(alert.detail.contains("no matching query retained"));
    let rule = alert.provenance.as_ref().unwrap();
    assert_eq!(rule.rule_id, "dns.unmatched_response");
    assert_eq!(rule.revision, 4);
    assert_eq!(rule.confidence.to_string(), "Heuristic");
    assert!(core.incidents.incidents.is_empty());

    // The same tuple is ordinary traffic when the query is visible.
    let query = dns_packet(2, false, "10.0.0.5", "10.0.0.53", 7, "safe.example");
    let reply = dns_packet(3, true, "10.0.0.53", "10.0.0.5", 7, "safe.example");
    core.analyze(&query);
    core.analyze(&reply);
    assert_eq!(core.alert_center.items.len(), 1);
    assert_eq!(core.alert_center.items[0].hit_count, 1);
    assert_eq!(core.alert_center.items[0].packet_refs, [1]);
}

#[test]
fn detects_unexpected_and_competing_responses() {
    let mut tracker = DnsTransactionTracker::default();

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
fn dns_integrity_keeps_transactions_and_alert_evidence_within_capture_scope() {
    let baseline = (0, 0, Some(20), Some(10));
    for other in [
        (1, 0, Some(20), Some(10)),
        (0, 1, Some(20), Some(10)),
        (0, 0, Some(21), Some(10)),
        (0, 0, Some(20), Some(11)),
        (0, 0, None, None),
    ] {
        let mut core = AnalysisCore::default();
        for (no, response, name, resolver, scope) in [
            (1, false, "one.example", "10.0.0.53", baseline),
            (2, false, "two.example", "10.0.0.54", other),
            (3, true, "one.example", "10.0.0.53", baseline),
            (4, true, "two.example", "10.0.0.54", other),
            (5, true, "one.example", "10.0.0.55", baseline),
            (6, true, "two.example", "10.0.0.55", other),
        ] {
            let (source, destination) = if response {
                (resolver, "10.0.0.5")
            } else {
                ("10.0.0.5", resolver)
            };
            let mut packet = dns_packet(no, response, source, destination, 7, name);
            let (section, interface, outer, inner) = scope;
            packet.outer_vlan_id = outer;
            packet.vlan_id = inner;
            packet.capture = Some(CaptureMetadata {
                timestamp: Some(CaptureTimestamp {
                    ticks: no,
                    resolution: TimestampResolution::Decimal(0),
                    offset_seconds: 0,
                }),
                captured_length: u32::from(packet.length),
                wire_length: u32::from(packet.length),
                link_type: 1,
                interface_id: interface,
                section_id: section,
                interface_name: None,
                comments: Vec::new(),
            });
            core.analyze(&packet);
        }
        let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| {
            alert.provenance.as_ref().is_some_and(|p| p.rule_id.starts_with("dns."))
        }).collect();
        assert_eq!(alerts.len(), 2, "{other:?}");
        for (last_packet, expected) in [(5, [1, 3, 5]), (6, [2, 4, 6])] {
            let alert = alerts.iter().find(|a| a.last_packet == last_packet).unwrap();
            let rule = alert.provenance.as_ref().unwrap();
            assert_eq!(rule.rule_id, "dns.competing_responders");
            assert_eq!(rule.revision, 3);
            assert_eq!(alert.hit_count, 1);
            assert_eq!(alert.packet_refs, expected, "{other:?}");
        }
    }
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
fn reports_only_semantic_changes_for_supported_dns_answers() {
    let mut engine = SecurityEngine::default();
    let query = dns_packet(1, false, "10.0.0.5", "10.0.0.53", 49, "safe.example");
    let mut reply = dns_packet(2, true, "10.0.0.53", "10.0.0.5", 49, "safe.example");
    append_answer(&mut reply, &[0xc0, 0x0c], 1, 300, &[192, 0, 2, 1]);
    append_answer(&mut reply, &[0xc0, 0x0c], 5, 300, &[0xc0, 0x11]);
    let mut reordered = dns_packet(3, true, "10.0.0.53", "10.0.0.5", 49, "safe.example");
    let owner = b"\x04SAFE\x07EXAMPLE\0";
    append_answer(&mut reordered, owner, 5, 299, b"\x07EXAMPLE\0");
    append_answer(&mut reordered, owner, 1, 299, &[192, 0, 2, 1]);

    engine.update(&query);
    engine.update(&reply);
    engine.update(&reply);
    engine.update(&reordered);
    assert!(engine.ids_alerts.is_empty());

    reordered.no = 4;
    reordered.timestamp = 4.0;
    *reordered.bytes.last_mut().unwrap() = 2;
    let batch = engine.inspect(&reordered);
    assert_eq!(engine.ids_alerts.len(), 1);
    assert_eq!(engine.ids_alerts[0].signature, "DNS answer set changed at the same resolver");
    assert_eq!(engine.ids_alerts[0].severity, Severity::Medium);
    assert_eq!(batch.ids[0].related_packets, [1, 2]);
}

#[test]
fn unsupported_dns_answer_changes_remain_low_confidence_wire_findings() {
    let mut engine = SecurityEngine::default();
    let query = dns_packet(1, false, "10.0.0.5", "10.0.0.53", 49, "safe.example");
    let mut reply = dns_packet(2, true, "10.0.0.53", "10.0.0.5", 49, "safe.example");
    append_answer(&mut reply, &[0xc0, 0x0c], 65_280, 300, &[1]);
    engine.update(&query);
    engine.update(&reply);
    engine.update(&reply);
    assert!(engine.ids_alerts.is_empty());

    *reply.bytes.last_mut().unwrap() = 2;
    engine.update(&reply);
    assert_eq!(engine.ids_alerts.len(), 1);
    assert_eq!(engine.ids_alerts[0].signature, "DNS reply changed at the same resolver");
    assert_eq!(engine.ids_alerts[0].severity, Severity::Low);
}

#[test]
fn standard_dns_response_code_changes_are_semantic() {
    let mut tracker = DnsTransactionTracker::default();
    let query = dns_packet(1, false, "10.0.0.5", "10.0.0.53", 49, "safe.example");
    let mut reply = dns_packet(2, true, "10.0.0.53", "10.0.0.5", 49, "safe.example");
    assert!(tracker.observe(&query).is_empty());
    assert!(tracker.observe(&reply).is_empty());
    reply.bytes[45] = 0x83;
    assert_eq!(tracker.observe(&reply)[0].kind, DnsFindingKind::ChangedAnswerSet);
}

#[test]
fn incomplete_udp_datagrams_do_not_enter_dns_correlation() {
    let mut tracker = DnsTransactionTracker::default();
    let query = dns_packet(1, false, "10.0.0.5", "10.0.0.53", 49, "safe.example");
    let mut reply = dns_packet(2, true, "10.0.0.53", "10.0.0.5", 49, "safe.example");
    let valid = reply.clone();
    assert!(tracker.observe(&query).is_empty());
    reply.bytes[20] = 0x20; // More fragments.
    reply.bytes[45] = 0x83;
    assert!(tracker.observe(&reply).is_empty());
    reply.bytes[20] = 0;
    let udp_length = u16::from_be_bytes(reply.bytes[38..40].try_into().unwrap()) + 4;
    reply.bytes[38..40].copy_from_slice(&udp_length.to_be_bytes());
    assert!(tracker.observe(&reply).is_empty());
    assert!(tracker.observe(&valid).is_empty());
}

#[test]
fn new_query_can_reuse_a_recently_completed_transaction_id() {
    let mut tracker = DnsTransactionTracker::default();
    for (no, name) in [(1, "first.example"), (3, "next.example")] {
        let query = dns_packet(no, false, "10.0.0.5", "10.0.0.53", 49, name);
        let reply = dns_packet(no + 1, true, "10.0.0.53", "10.0.0.5", 49, name);
        assert!(tracker.observe(&query).is_empty());
        assert!(tracker.observe(&reply).is_empty());
    }
}

#[test]
fn parallel_dns_queries_can_reuse_the_same_id_and_port() {
    let client = "10.0.0.5";
    for (second_resolver, second_question) in [
        ("10.0.0.54", "first.example"),
        ("10.0.0.53", "second.example"),
        ("10.0.0.54", "second.example"),
    ] {
        let mut tracker = DnsTransactionTracker::default();
        for packet in [
            dns_packet(1, false, client, "10.0.0.53", 42, "first.example"),
            dns_packet(2, false, client, second_resolver, 42, second_question),
            dns_packet(3, true, second_resolver, client, 42, second_question),
            dns_packet(4, true, "10.0.0.53", client, 42, "first.example"),
            dns_packet(5, true, second_resolver, client, 42, second_question),
        ] {
            assert!(tracker.observe(&packet).is_empty(), "frame {}", packet.no);
        }
    }
}

#[test]
fn ambiguous_reply_does_not_consume_candidate_queries() {
    let mut core = AnalysisCore::default();
    let client = "10.0.0.5";
    for packet in [
        dns_packet(1, false, client, "10.0.0.53", 42, "first.example"),
        dns_packet(2, false, client, "10.0.0.54", 42, "second.example"),
        dns_packet(3, true, "10.0.0.53", client, 42, "second.example"),
        dns_packet(4, true, "10.0.0.53", client, 42, "first.example"),
        dns_packet(5, true, "10.0.0.54", client, 42, "second.example"),
        dns_packet(6, true, "10.0.0.55", client, 42, "first.example"),
    ] {
        core.analyze(&packet);
    }
    let by_rule = |rule_id| core.alert_center.items.iter().find(|alert| {
        alert.provenance.as_ref().is_some_and(|p| p.rule_id == rule_id)
    }).unwrap();
    assert_eq!(core.alert_center.items.len(), 2);
    let ambiguous = by_rule("dns.ambiguous_reply");
    assert_eq!(ambiguous.severity, "LOW");
    assert_eq!(ambiguous.packet_refs, [3]);
    let conflict = by_rule("dns.competing_responders");
    assert_eq!(conflict.severity, "CRITICAL");
    assert_eq!(conflict.packet_refs, [1, 4, 6]);
}

#[test]
fn dns_collision_bucket_bounds_candidates_without_guessing_on_overflow() {
    let mut tracker = DnsTransactionTracker::default();
    let client = "10.0.0.5";
    let resolver = "10.0.0.53";
    for number in 1..=6 {
        let query = dns_packet(number, false, client, resolver, 42, &format!("name{number}.example"));
        assert!(tracker.observe(&query).is_empty());
    }
    let reply = dns_packet(7, true, resolver, client, 42, "name6.example");
    assert_eq!(tracker.observe(&reply)[0].kind, DnsFindingKind::AmbiguousReply);
    let retained = dns_packet(8, true, resolver, client, 42, "name1.example");
    assert!(tracker.observe(&retained).is_empty());
    let query = dns_packet(40, false, client, resolver, 42, "reused.example");
    let reply = dns_packet(41, true, resolver, client, 42, "reused.example");
    assert!(tracker.observe(&query).is_empty());
    assert!(tracker.observe(&reply).is_empty());
}

#[test]
fn nxdomain_burst_counts_distinct_matched_names_and_keeps_packet_pairs() {
    let mut core = AnalysisCore::default();
    let make = |no: u64, id, name: &str, flags, vlan, opt_ext: Option<u8>| {
        let mut query = dns_packet(no, false, "10.0.0.5", "10.0.0.53", id, name);
        let mut reply = dns_packet(no + 1, true, "10.0.0.53", "10.0.0.5", id, name);
        query.timestamp = no as f64 / 100.0;
        reply.timestamp = (no + 1) as f64 / 100.0;
        query.vlan_id = Some(vlan);
        reply.vlan_id = Some(vlan);
        reply.info = "Summary contains NXDOMAIN".into();
        reply.bytes[44..46].copy_from_slice(&u16::to_be_bytes(flags));
        if let Some(extended) = opt_ext {
            reply.bytes[53] = 1; // ARCOUNT.
            reply.bytes.extend([0, 0, 41, 4, 0, extended, 0, 0, 0, 0, 0]);
            reply.length = reply.bytes.len() as u16;
            reply.bytes[16..18].copy_from_slice(&(reply.length - 14).to_be_bytes());
            reply.bytes[38..40].copy_from_slice(&(reply.length - 34).to_be_bytes());
        }
        [query, reply]
    };
    for i in 1..=20_u16 {
        for pair in [
            make(u64::from(i * 8), i, "Repeated.example", 0x8183, 20, None),
            make(u64::from(i * 8 + 2), i + 20, &format!("ok{i}.example"), 0x8180, 30, None),
            make(u64::from(i * 8 + 4), i + 40, &format!("trunc{i}.example"), 0x8383, 30, None),
            make(u64::from(i * 8 + 6), i + 60, &format!("edns{i}.example"), 0x8183, 30, Some(1)),
        ] {
            for packet in &pair {
                core.analyze(packet);
            }
            core.analyze(&pair[1]); // Duplicate response.
        }
    }
    for i in 1..=19_u16 {
        for packet in make(200 + u64::from(2 * i), i + 100, &format!("miss{i}.example"), 0x8183, 10, None) {
            core.analyze(&packet);
        }
    }
    assert!(core.alert_center.items.iter().all(|a| a.title != "DNS NXDOMAIN burst"));
    for packet in make(240, 120, "miss20.example", 0x8183, 10, Some(0)) {
        core.analyze(&packet);
    }
    let alert = core.alert_center.items.iter().find(|a| a.title == "DNS NXDOMAIN burst").unwrap();
    let mut evidence = alert.packet_refs.clone();
    evidence.sort_unstable();
    assert_eq!(evidence, (202..=241).collect::<Vec<_>>());
    assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "dns.nxdomain_distinct_names");
    assert_eq!(alert.severity, "MEDIUM");
    assert!(core.incidents.incidents.is_empty());
}

#[test]
fn dns_conflict_exports_the_query_and_both_replies_as_one_hit() {
    let mut core = AnalysisCore::default();
    for (first_packet, transaction_id) in [(1, 49), (4, 50)] {
        let query = dns_packet(first_packet, false, "10.0.0.5", "10.0.0.53", transaction_id, "safe.example");
        let reply = dns_packet(first_packet + 1, true, "10.0.0.53", "10.0.0.5", transaction_id, "safe.example");
        let conflict = dns_packet(first_packet + 2, true, "10.0.0.54", "10.0.0.5", transaction_id, "safe.example");
        for packet in [query, reply, conflict] {
            core.analyze_with_history(&packet, std::iter::empty());
        }
    }
    let alerts = core.alert_center.drain_pending_exports();
    let conflicts: Vec<_> = alerts
        .iter()
        .filter(|alert| alert.title == "Conflicting DNS responses")
        .collect();
    assert_eq!(conflicts.len(), 2);
    assert_eq!(conflicts[0].hit_count, 1);
    assert_eq!(conflicts[0].packet_refs, [1, 2, 3]);
    assert_eq!(conflicts[1].id, conflicts[0].id);
    assert_eq!(conflicts[1].hit_count, 2);
    assert_eq!(conflicts[1].packet_no, 6);
    assert_eq!(conflicts[1].packet_refs, [1, 2, 3, 4, 5, 6]);
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
