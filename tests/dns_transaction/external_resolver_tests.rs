use super::*;

#[test]
fn detects_external_resolver_use() {
    let mut core = AnalysisCore::default();
    let client = "10.0.0.5";
    let public = "8.8.8.8";
    const TITLE: &str = "Direct external DNS resolver use";
    let mut fake = dns_packet(1, false, client, public, 1, "example.test");
    fake.bytes.truncate(43);
    core.analyze(&fake);
    for (index, target) in [
        "10.0.0.53", "100.64.0.53", "192.0.2.53", "198.18.0.53", "224.0.0.53",
    ].into_iter().enumerate() {
        let no = 2 + index as u64 * 2;
        core.analyze(&dns_packet(no, false, client, target, 2, "example.test"));
        core.analyze(&dns_packet(no + 1, true, target, client, 2, "example.test"));
    }
    let query = dns_packet(12, false, client, public, 3, "example.test");
    let reply = dns_packet(13, true, public, client, 3, "example.test");
    core.analyze(&query);
    assert!(core.alert_center.items.iter().all(|a| a.title != TITLE));
    core.analyze(&reply);
    core.analyze(&dns_packet(14, false, client, public, 4, "example.test"));
    core.analyze(&dns_packet(15, true, public, client, 4, "example.test"));

    let mut query = dns_packet(16, false, client, public, 5, "example.test");
    let mut reply = dns_packet(17, true, public, client, 5, "example.test");
    query.vlan_id = Some(10);
    reply.vlan_id = Some(10);
    core.analyze(&query);
    core.analyze(&reply);
    let findings: Vec<_> = core.alert_center.items.iter().filter(|a| a.title == TITLE).collect();
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].packet_refs, [12, 13]);
    assert_eq!(findings[1].packet_refs, [16, 17]);
    assert!(findings.iter().all(|a| a.severity == "LOW" && a.hit_count == 1));
    assert_eq!(findings[0].provenance.as_ref().unwrap().rule_id, "dns.external_resolver_exchange");
    assert!(findings[0].detail.contains("resolver policy not verified"));
}

#[test]
fn expected_external_exchange_is_still_reported_after_a_competing_reply() {
    let mut tracker = DnsTransactionTracker::default();
    let client = "10.0.0.5";
    let public = "8.8.8.8";
    assert!(tracker.observe(&dns_packet(1, false, client, public, 6, "example.test")).is_empty());
    let other = tracker.observe(&dns_packet(2, true, "9.9.9.9", client, 6, "example.test"));
    assert_eq!(other.len(), 1);
    assert_eq!(other[0].kind, DnsFindingKind::UnexpectedResponder);
    let reply = tracker.observe(&dns_packet(3, true, public, client, 6, "example.test"));
    assert_eq!(reply.len(), 2);
    assert_eq!(reply[0].kind, DnsFindingKind::ConflictingResponse);
    assert_eq!(reply[0].related_packets, [1, 2]);
    assert_eq!(reply[1].kind, DnsFindingKind::ExternalResolver);
    assert_eq!(reply[1].related_packets, [1]);
    assert!(tracker.observe(&dns_packet(4, true, public, client, 6, "example.test")).is_empty());
}

#[test]
fn external_ipv6_resolver_rule_excludes_documentation_and_multicast() {
    let mut tracker = DnsTransactionTracker::default();
    for (i, server) in ["2001:db8::53", "ff02::53", "fd00::53", "2606:4700:4700::1111"].into_iter().enumerate() {
        let no = 2 * i as u64 + 1;
        assert!(tracker.observe(&dns_ipv6_packet(no, false, "fd00::5", server, 5, "example.test")).is_empty());
        let findings = tracker.observe(&dns_ipv6_packet(no + 1, true, server, "fd00::5", 5, "example.test"));
        if i == 3 {
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].kind, DnsFindingKind::ExternalResolver);
            assert_eq!(findings[0].related_packets, [no]);
        } else {
            assert!(findings.is_empty());
        }
    }
}
