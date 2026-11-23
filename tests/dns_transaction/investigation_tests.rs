use super::*;

#[test]
fn dns_correlation_uses_frame_order_for_tied_timestamps() {
    let mut tracker = DnsTransactionTracker::default();
    let query = |no| {
        let mut packet = dns_packet(no, false, "10.0.0.5", "10.0.0.53", 50, "safe.example");
        packet.timestamp = 1.0;
        packet
    };
    let reply = |no, resolver| {
        let mut packet = dns_packet(no, true, resolver, "10.0.0.5", 50, "safe.example");
        packet.timestamp = 1.0;
        packet
    };
    assert!(tracker.observe(&query(10)).is_empty());
    let earlier = tracker.observe(&reply(9, "10.0.0.54"));
    assert_eq!(earlier[0].kind, DnsFindingKind::ReplyWithoutObservedQuery);
    assert!(earlier[0].related_packets.is_empty());
    assert!(tracker.observe(&reply(11, "10.0.0.53")).is_empty());
    assert!(tracker.observe(&query(8)).is_empty());

    let findings = tracker.observe(&reply(12, "10.0.0.54"));
    assert_eq!(findings[0].kind, DnsFindingKind::ConflictingResponse);
    assert_eq!(findings[0].related_packets, [10, 11]);
}

#[test]
fn dns_tunnel_lead_requires_distinct_scoped_wire_queries() {
    const TITLE: &str = "DNS tunnel behavior";
    const LABEL: &str = "abcdefghijklmnpqrstuvwxyz234567";
    let client = "10.0.0.5";
    let resolver = "10.0.0.53";
    let make = |no: u64, index, response, vlan, client, resolver| {
        let name = format!("{LABEL}{index}.example.test");
        let (src, dst) = if response { (resolver, client) } else { (client, resolver) };
        let mut packet = dns_packet(no, response, src, dst, no as u16, &name);
        packet.vlan_id = Some(vlan);
        packet
    };
    let mut core = AnalysisCore::default();
    let mut display_only = make(1, 1, false, 10, client, resolver);
    display_only.bytes.clear();
    display_only.info = format!("Query {LABEL}.example.test");
    core.analyze(&display_only);
    for no in 2..=8 {
        core.analyze(&make(no, no, false, 10, client, resolver));
    }
    core.analyze(&make(9, 2, false, 10, client, resolver)); // Repeated wire name.
    core.analyze(&make(10, 10, false, 20, client, resolver));
    core.analyze(&make(11, 11, false, 10, "10.0.0.8", resolver));
    core.analyze(&make(12, 12, false, 10, client, "10.0.0.54"));
    core.analyze(&make(13, 13, true, 10, client, resolver));
    let mut late = make(14, 14, false, 10, client, resolver);
    late.timestamp = 1.0;
    core.analyze(&late);
    assert!(core.alert_center.items.iter().all(|alert| alert.title != TITLE));

    core.analyze(&make(15, 15, false, 10, client, resolver));
    let alert = core.alert_center.items.iter().find(|alert| alert.title == TITLE).unwrap();
    assert_eq!(alert.packet_refs, (2..=8).chain([15]).collect::<Vec<_>>());
    assert_eq!(alert.severity, "MEDIUM");
    assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "dns.high_entropy_query_burst");
    assert!(alert.detail.contains("tunneling and data transfer unverified"));
    assert!(!serde_json::to_string(alert).unwrap().contains(LABEL));

    core.analyze(&make(120, 120, false, 10, client, resolver));
    assert_eq!(core.alert_center.items.iter().filter(|alert| alert.title == TITLE).count(), 1);
}

#[rstest::rstest]
#[case("co.uk")]
#[case("github.io")]
fn dns_high_entropy_queries_do_not_combine_unrelated_registered_domains(#[case] suffix: &str) {
    const TITLE: &str = "DNS tunnel behavior";
    let mut core = AnalysisCore::default();
    let query = |no, tenant| {
        let name = format!("abcdefghijklmnpqrstuvwxyz234567{no}.{tenant}.{suffix}");
        dns_packet(no, false, "10.0.0.5", "10.0.0.53", no as u16, &name)
    };
    for no in 1..=8 {
        core.analyze(&query(no, if no % 2 == 0 { "alpha" } else { "bravo" }));
    }
    assert!(core.alert_center.items.iter().all(|alert| alert.title != TITLE));
    for no in 9..=12 {
        core.analyze(&query(no, "alpha"));
    }
    let alert = core.alert_center.items.iter().find(|alert| alert.title == TITLE).unwrap();
    assert_eq!(alert.packet_refs, [2, 4, 6, 8, 9, 10, 11, 12]);
    assert!(alert.detail.contains(&format!("under alpha.{suffix} ")));
}

#[test]
fn truncated_replies_are_retained_but_complete_replies_anchor_dns_comparison() {
    let client = "10.0.0.5";
    let resolver = "10.0.0.53";
    let mut tracker = DnsTransactionTracker::default();
    let query = dns_packet(1, false, client, resolver, 69, "example.test");
    let mut truncated = dns_packet(2, true, resolver, client, 69, "example.test");
    truncated.bytes[44] |= 0x02;
    let mut full = dns_packet(3, true, resolver, client, 69, "example.test");
    append_answer(&mut full, &[0xc0, 0x0c], 1, 300, &[192, 0, 2, 1]);
    let mut partial = dns_packet(4, true, resolver, client, 69, "example.test");
    partial.bytes[44] |= 0x02;
    append_answer(&mut partial, &[0xc0, 0x0c], 1, 300, &[192, 0, 2, 2]);
    for packet in [&query, &truncated, &full, &partial] {
        assert!(tracker.observe(packet).is_empty(), "frame {}", packet.no);
    }

    let mut changed = dns_packet(5, true, resolver, client, 69, "example.test");
    append_answer(&mut changed, &[0xc0, 0x0c], 1, 300, &[192, 0, 2, 2]);
    let result = tracker.observe(&changed);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].kind, DnsFindingKind::ChangedAnswerSet);
    assert_eq!(result[0].related_packets, [1, 3]);
    let replies = tracker.exchange_for_packet(&query).unwrap().replies;
    assert_eq!(
        replies.iter().map(|reply| (reply.packet, reply.truncated)).collect::<Vec<_>>(),
        [(2, true), (3, false), (4, true), (5, false)]
    );

    let mut competing = dns_packet(6, true, "10.0.0.54", client, 69, "example.test");
    competing.bytes[44] |= 0x02;
    let result = tracker.observe(&competing);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].kind, DnsFindingKind::ConflictingResponse);
    assert_eq!(result[0].related_packets, [1, 3]);
}

#[test]
fn queried_resolver_anchors_answer_comparison_even_when_another_resolver_replies_first() {
    let client = "10.0.0.5";
    let resolver = "10.0.0.53";
    let other = "10.0.0.54";
    let query = dns_packet(1, false, client, resolver, 70, "example.test");
    let reply = |no, source, last_octet, ttl| {
        let mut packet = dns_packet(no, true, source, client, 70, "example.test");
        append_answer(&mut packet, &[0xc0, 0x0c], 1, ttl, &[192, 0, 2, last_octet]);
        packet
    };

    let mut tracker = DnsTransactionTracker::default();
    assert!(tracker.observe(&query).is_empty());
    let unexpected = tracker.observe(&reply(2, other, 10, 300));
    assert_eq!(unexpected[0].kind, DnsFindingKind::UnexpectedResponder);
    let conflict = tracker.observe(&reply(3, resolver, 1, 300));
    assert_eq!(conflict[0].kind, DnsFindingKind::ConflictingResponse);
    assert_eq!(conflict[0].related_packets, [1, 2]);

    assert!(tracker.observe(&reply(4, resolver, 1, 299)).is_empty());
    let changed = tracker.observe(&reply(5, resolver, 2, 298));
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].kind, DnsFindingKind::ChangedAnswerSet);
    assert_eq!(changed[0].related_packets, [1, 3]);
    let conflict = tracker.observe(&reply(6, other, 11, 300));
    assert_eq!(conflict[0].kind, DnsFindingKind::ConflictingResponse);
    assert_eq!(conflict[0].related_packets, [1, 3]);
}

#[test]
fn edns_reply_comparison_uses_validated_full_response_codes() {
    fn add_opt(reply: &mut Packet, payload: u16, ext_rcode: u8, options: &[u8]) {
        reply.bytes[53] = 1; // ARCOUNT.
        reply.bytes.extend([0, 0, 41]);
        reply.bytes.extend(payload.to_be_bytes());
        reply.bytes.extend([ext_rcode, 0, 0, 0]);
        reply.bytes.extend((options.len() as u16).to_be_bytes());
        reply.bytes.extend(options);
        reply.length = reply.bytes.len() as u16;
        reply.bytes[16..18].copy_from_slice(&(reply.length - 14).to_be_bytes());
        reply.bytes[38..40].copy_from_slice(&(reply.length - 34).to_be_bytes());
    }

    let client = "10.0.0.5";
    let resolver = "10.0.0.53";
    let mut tracker = DnsTransactionTracker::default();
    let query = dns_packet(1, false, client, resolver, 69, "example.test");
    let plain = dns_packet(2, true, resolver, client, 69, "example.test");
    let mut metadata_change = dns_packet(3, true, resolver, client, 69, "example.test");
    add_opt(&mut metadata_change, 1232, 0, &[0, 12, 0, 2, 0, 0]);
    let mut code_change = dns_packet(4, true, resolver, client, 69, "example.test");
    append_answer(&mut code_change, &[0xc0, 0x0c], 65_280, 300, &[1]);
    add_opt(&mut code_change, 1232, 1, &[]);
    let mut malformed = dns_packet(5, true, resolver, client, 69, "example.test");
    add_opt(&mut malformed, 1232, 1, &[0, 12, 0, 4, 0, 0]);
    for packet in [&query, &plain, &metadata_change] {
        assert!(tracker.observe(packet).is_empty());
    }
    let changed = tracker.observe(&code_change);
    assert_eq!(changed[0].kind, DnsFindingKind::ChangedAnswerSet);
    assert_eq!(changed[0].related_packets, [1, 2]);
    assert!(changed[0].detail.contains("response code (0 to 16)"));
    let weak = tracker.observe(&malformed);
    assert_eq!(weak[0].kind, DnsFindingKind::ChangedReply);
    assert!(weak[0].detail.contains("answer comparison unavailable"));
    let evidence = tracker.exchange_for_packet(&query).unwrap();
    assert_eq!(evidence.replies.iter().map(|reply| reply.response_code).collect::<Vec<_>>(),
        [Some(0), Some(16), None]);
}

#[test]
fn repeated_pending_dns_queries_keep_the_original_alert_anchor() {
    let client = "10.0.0.5";
    let resolver = "10.0.0.53";
    let query = dns_packet(1, false, client, resolver, 33, "example.test");
    let mut retry = dns_packet(2, false, client, resolver, 33, "example.test");
    let mut reply = dns_packet(3, true, resolver, client, 33, "example.test");
    let mut alternate = dns_packet(4, true, "10.0.0.54", client, 33, "example.test");
    retry.timestamp = 29.0;
    reply.timestamp = 32.0;
    alternate.timestamp = 33.0;
    let mut core = AnalysisCore::default();
    for packet in [&query, &retry, &retry, &reply, &alternate] {
        core.analyze(packet);
    }
    let conflict = core.alert_center.items.iter().find(|alert| {
        alert.provenance.as_ref().is_some_and(|rule| rule.rule_id == "dns.competing_responders")
    }).unwrap();
    assert_eq!(conflict.packet_refs, [1, 3, 2, 4]);
    for frame in [&query, &retry, &reply, &alternate] {
        let evidence = core.security.dns_exchange_for_packet(frame).unwrap();
        assert_eq!(evidence.query_packet, 1);
        assert_eq!(evidence.repeated_query_packets, [2]);
        assert!(!evidence.additional_queries_omitted);
    }
}

#[test]
fn pending_repeats_cannot_extend_dns_exchange_state_indefinitely() {
    let mut tracker = DnsTransactionTracker::default();
    let client = "10.0.0.5";
    let resolver = "10.0.0.53";
    let query = dns_packet(1, false, client, resolver, 34, "example.test");
    tracker.observe(&query);
    for (frame, timestamp) in [(2, 3.0), (3, 7.0), (4, 17.0), (5, 37.0), (6, 59.0)] {
        let mut retry = dns_packet(frame, false, client, resolver, 34, "example.test");
        retry.timestamp = timestamp;
        tracker.observe(&retry);
    }
    let evidence = tracker.exchange_for_packet(&query).unwrap();
    assert_eq!(evidence.repeated_query_packets, [2, 3, 4, 5]);
    assert!(evidence.additional_queries_omitted);
    let mut late = dns_packet(7, true, resolver, client, 34, "example.test");
    late.timestamp = 62.0;
    assert_eq!(tracker.observe(&late)[0].kind, DnsFindingKind::ReplyWithoutObservedQuery);
    assert!(tracker.exchange_for_packet(&query).is_none());
}

#[test]
fn dns_query_with_the_same_question_but_different_wire_flags_is_not_a_repeat() {
    let mut tracker = DnsTransactionTracker::default();
    let client = "10.0.0.5";
    let resolver = "10.0.0.53";
    let query = dns_packet(1, false, client, resolver, 35, "example.test");
    let mut changed = dns_packet(2, false, client, resolver, 35, "example.test");
    changed.bytes[44] ^= 0x01;
    tracker.observe(&query);
    tracker.observe(&changed);
    assert!(tracker.exchange_for_packet(&query).is_none());
    let evidence = tracker.exchange_for_packet(&changed).unwrap();
    assert_eq!(evidence.query_packet, 2);
    assert!(evidence.repeated_query_packets.is_empty());
}

#[test]
fn invalid_dns_question_counts_are_reported_but_do_not_enter_correlation() {
    let client = "10.0.0.5";
    let resolver = "10.0.0.53";
    let other = "10.0.0.54";
    let mut core = AnalysisCore::default();
    let query = dns_packet(1, false, client, resolver, 60, "example.test");
    let mut malformed_query = query.clone();
    malformed_query.bytes[46..48].copy_from_slice(&2_u16.to_be_bytes());
    core.analyze(&malformed_query);
    assert!(core.security.dns_exchange_for_packet(&malformed_query).is_none());

    for (no, opcode, count) in [(2, 0, 0_u16), (3, 4, 1), (4, 5, 2)] {
        for response in [false, true] {
            let (src, dst) = if response { (resolver, client) } else { (client, resolver) };
            let mut unsupported = dns_packet(no, response, src, dst, 60, "example.test");
            unsupported.bytes[44] |= opcode << 3;
            unsupported.bytes[46..48].copy_from_slice(&count.to_be_bytes());
            core.analyze(&unsupported);
            assert!(core.security.dns_exchange_for_packet(&unsupported).is_none());
        }
    }
    assert_eq!(core.alert_center.items.len(), 1);
    let reply = dns_packet(5, true, resolver, client, 60, "example.test");
    core.analyze(&reply);
    assert_eq!(core.alert_center.items[1].title, "DNS reply without observed query");

    let query = dns_packet(6, false, client, resolver, 60, "example.test");
    let reply = dns_packet(7, true, resolver, client, 60, "example.test");
    let mut malformed_reply = dns_packet(8, true, other, client, 60, "example.test");
    malformed_reply.bytes[46..48].copy_from_slice(&2_u16.to_be_bytes());
    for packet in [&query, &reply, &malformed_reply] {
        core.analyze(packet);
    }
    assert_eq!(core.alert_center.items.len(), 3);
    for (index, frame) in [(0, 1), (2, 8)] {
        let alert = &core.alert_center.items[index];
        assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "dns.invalid_question_count");
        assert_eq!(alert.severity, "LOW");
        assert_eq!(alert.packet_refs, [frame]);
        assert!(alert.detail.contains("declares 2 questions"));
    }
    assert!(core.security.dns_exchange_for_packet(&malformed_reply).is_none());
    assert_eq!(core.security.dns_exchange_for_packet(&query).unwrap().replies.len(), 1);
    assert!(core.incidents.incidents.is_empty());
}

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
