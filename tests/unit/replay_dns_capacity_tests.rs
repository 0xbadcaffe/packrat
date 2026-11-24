use super::*;

#[test]
fn dns_detector_capacity_limits_are_not_applied_to_other_rules() {
    let negative = DnsCapacityStats { nxdomain_client_declines: 1, ..Default::default() };
    let external = DnsCapacityStats { external_resolver_pair_declines: 1, ..Default::default() };
    let candidate = DnsCapacityStats { query_candidate_declines: 1, ..Default::default() };
    assert!(dns_rule_limited("dns.nxdomain_distinct_names", negative));
    assert!(!dns_rule_limited("dns.external_resolver_exchange", negative));
    assert!(dns_rule_limited("dns.external_resolver_exchange", external));
    assert!(!dns_rule_limited("dns.nxdomain_distinct_names", external));
    assert!(!dns_rule_limited("dns.changed_answers", negative));
    assert!(!dns_rule_limited("dns.changed_answers", external));
    assert!(dns_rule_limited("dns.changed_answers", candidate));
    assert!(!dns_rule_limited("dns.invalid_question_count", candidate));
    assert!(!dns_rule_limited("dns.jndi_question_label", candidate));
    assert!(!dns_rule_limited("dns.high_entropy_query_burst", candidate));
}
