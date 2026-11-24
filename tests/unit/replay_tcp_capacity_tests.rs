use super::*;

#[test]
fn stream_evictions_limit_only_tcp_dependent_expectations() {
    let mut replay = ReplayAlerts::default();
    replay.expect("scan.horizontal=0").unwrap();
    assert_eq!(replay.evaluate(true, Default::default(), 1).unwrap().verdict, "passed");
    for id in ["tls.tls10_selected", "http.unauthorized_burst", "industrial.state_change", "dns.unmatched_response"] {
        assert!(uses_tcp_stream_cache(id));
    }
    for id in ["scan.horizontal", "tcp.conflicting_retransmission", "http.cleartext_basic_authorization"] {
        assert!(!uses_tcp_stream_cache(id));
    }
    replay.expect("http.unauthorized_burst=0").unwrap();
    assert_eq!(replay.evaluate(true, Default::default(), 0).unwrap().verdict, "passed");
    let limited = replay.evaluate(true, Default::default(), 1).unwrap();
    assert_eq!(limited.verdict, "inconclusive");
    assert_eq!(limited.tcp_stream_limited_rules, ["http.unauthorized_burst"]);
    assert!(limited.dns_capacity_limited_rules.is_empty());
}
