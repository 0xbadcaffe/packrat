use super::*;

#[test]
fn dns_mismatched_questions_do_not_become_competing_reply_evidence() {
    let client = "10.0.0.5";
    let resolver = "10.0.0.53";
    let other = "10.0.0.54";
    for mismatch_first in [false, true] {
        let mut core = AnalysisCore::default();
        let query = dns_packet(1, false, client, resolver, 61, "example.test");
        let mismatch_no = if mismatch_first { 2 } else { 3 };
        let matching_no = if mismatch_first { 3 } else { 2 };
        let mut mismatched = dns_packet(mismatch_no, true, resolver, client, 61, "example.test");
        let qtype = mismatched.bytes.len() - 4;
        mismatched.bytes[qtype..qtype + 2].copy_from_slice(&28_u16.to_be_bytes());
        let matching = dns_packet(matching_no, true, other, client, 61, "example.test");
        core.analyze(&query);
        for reply in if mismatch_first {
            [&mismatched, &matching]
        } else {
            [&matching, &mismatched]
        } {
            core.analyze(reply);
        }
        let by_rule = |rule_id| {
            core.alert_center.items.iter().find(|alert| {
                alert.provenance.as_ref().is_some_and(|p| p.rule_id == rule_id)
            })
        };
        assert!(by_rule("dns.competing_responders").is_none());
        let mismatch = by_rule("dns.question_mismatch").unwrap();
        assert_eq!(mismatch.packet_refs, [1, mismatch_no]);
        assert!(mismatch.detail.contains("type 28"));
        assert_eq!(by_rule("dns.unexpected_responder").unwrap().packet_refs, [1, matching_no]);

        let competing = dns_packet(4, true, resolver, client, 61, "example.test");
        core.analyze(&competing);
        let conflict = core.alert_center.items.iter().find(|alert| {
            alert.provenance.as_ref().is_some_and(|p| p.rule_id == "dns.competing_responders")
        }).unwrap();
        assert_eq!(conflict.packet_refs, [1, matching_no, 4]);
        let exchange = core.security.dns_exchange_for_packet(&mismatched).unwrap();
        assert_eq!(exchange.replies.iter().map(|reply| reply.packet).collect::<Vec<_>>(), [2, 3, 4]);
    }
}

#[test]
fn dns_investigation_links_query_normal_reply_and_competing_reply() {
    let mut tracker = DnsTransactionTracker::default();
    let query = dns_packet(1, false, "10.0.0.5", "10.0.0.53", 35, "example.test");
    let reply = dns_packet(2, true, "10.0.0.53", "10.0.0.5", 35, "example.test");
    let conflict = dns_packet(3, true, "10.0.0.54", "10.0.0.5", 35, "example.test");
    tracker.observe(&query);
    let pending = tracker.exchange_for_packet(&query).unwrap();
    assert!(pending.replies.is_empty());
    tracker.observe(&reply);
    tracker.observe(&conflict);
    for frame in [&query, &reply, &conflict] {
        let evidence = tracker.exchange_for_packet(frame).unwrap();
        assert_eq!(evidence.query_packet, 1);
        assert_eq!(evidence.transaction_id, 35);
        assert_eq!(evidence.expected_resolver, "10.0.0.53");
        assert_eq!(evidence.question, "example.test");
        assert_eq!(evidence.replies.iter().map(|reply| reply.packet).collect::<Vec<_>>(), [2, 3]);
        assert_eq!(evidence.replies[1].resolver, "10.0.0.54");
    }
    let mut unrelated = conflict.clone();
    unrelated.no = 25;
    assert!(tracker.exchange_for_packet(&unrelated).is_none());
    unrelated.no = 3;
    unrelated.vlan_id = Some(10);
    assert!(tracker.exchange_for_packet(&unrelated).is_none());

    let reused = dns_packet(4, false, "10.0.0.5", "10.0.0.53", 35, "example.test");
    tracker.observe(&reused);
    assert!(tracker.exchange_for_packet(&query).is_none());
    assert!(tracker.exchange_for_packet(&conflict).is_none());
    assert_eq!(tracker.exchange_for_packet(&reused).unwrap().query_packet, 4);
}

#[test]
fn dns_investigation_bounds_alternate_replies() {
    let mut tracker = DnsTransactionTracker::default();
    let query = dns_packet(1, false, "10.0.0.5", "10.0.0.53", 35, "example.test");
    tracker.observe(&query);
    for no in 2..=12 {
        let mut reply = dns_packet(no, true, &format!("10.0.0.{}", 51 + no), "10.0.0.5", 35, "example.test");
        reply.timestamp = no as f64 / 100.0 + 1.0;
        tracker.observe(&reply);
    }
    let evidence = tracker.exchange_for_packet(&query).unwrap();
    assert_eq!(evidence.replies.len(), 9);
    assert!(evidence.additional_replies_omitted);
}

#[test]
fn exact_copies_of_retained_alternate_dns_replies_do_not_increment_alert_hits() {
    let resolver = "10.0.0.53";
    let client = "10.0.0.5";
    for (source, rule) in [
        (resolver, "dns.changed_answers"),
        ("10.0.0.54", "dns.competing_responders"),
    ] {
        let mut core = AnalysisCore::default();
        let query = dns_packet(1, false, client, resolver, 47, "example.test");
        let reply = dns_packet(2, true, resolver, client, 47, "example.test");
        let mut alternate = dns_packet(3, true, source, client, 47, "example.test");
        alternate.bytes[45] = 0x83;
        let mut copy = alternate.clone();
        copy.no = 4;
        copy.timestamp = 3.1;
        let mut distinct = copy.clone();
        distinct.no = 5;
        distinct.timestamp = 3.2;
        distinct.bytes[45] = 0x82;
        for packet in [&query, &reply, &alternate, &copy, &distinct] {
            core.analyze(packet);
        }
        let finding = core.alert_center.items.iter().find(|alert| {
            alert.provenance.as_ref().is_some_and(|provenance| provenance.rule_id == rule)
        }).unwrap();
        assert_eq!(finding.hit_count, 2, "{rule}");
        assert_eq!(finding.packet_refs, [1, 2, 3, 5], "{rule}");
        let exchange = core.security.dns_exchange_for_packet(&query).unwrap();
        assert_eq!(exchange.replies.iter().map(|reply| reply.packet).collect::<Vec<_>>(), [2, 3, 5]);
    }
}

#[test]
fn dns_integrity_alerts_group_only_replies_to_the_same_observed_query() {
    let mut core = AnalysisCore::default();
    let client = "10.0.0.5";
    let resolver = "10.0.0.53";
    let alternate_a = "10.0.0.54";
    let alternate_b = "10.0.0.55";
    for packet in [
        dns_packet(1, false, client, resolver, 55, "first.example"),
        dns_packet(2, false, client, resolver, 56, "second.example"),
        dns_packet(3, true, resolver, client, 55, "first.example"),
        dns_packet(4, true, resolver, client, 56, "second.example"),
        dns_packet(5, true, alternate_a, client, 55, "first.example"),
        dns_packet(6, true, alternate_a, client, 56, "second.example"),
        dns_packet(7, true, alternate_b, client, 55, "first.example"),
    ] {
        core.analyze(&packet);
    }

    let alerts: Vec<_> = core.alert_center.items.iter()
        .filter(|alert| alert.title == "Conflicting DNS responses").collect();
    assert_eq!(alerts.len(), 2);
    assert_ne!(alerts[0].correlation_key, alerts[1].correlation_key);
    assert_eq!(alerts[0].hit_count, 2);
    assert_eq!(alerts[0].packet_refs, [1, 3, 5, 7]);
    assert_eq!(alerts[1].hit_count, 1);
    assert_eq!(alerts[1].packet_refs, [2, 4, 6]);
}
