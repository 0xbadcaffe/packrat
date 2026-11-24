use super::*;

#[test]
fn burst_cache_bounds_candidates_and_links_only_matching_scope_and_frames() {
    let source = ((None, Some(10), None), [2, 1, 2, 3, 4, 5]);
    let other = ((None, Some(20), None), source.1);
    let mut cache = RouterRateEvidence::default();
    for no in 1..=MAX_ROUTER_RATE_EVIDENCE as u64 + 1 {
        let candidate = crate::net::parser::parse_ethernet(&[0; 14], no, 1.0);
        cache.remember(if no == 2 { other } else { source }, &candidate);
    }
    assert_eq!(cache.0.len(), MAX_ROUTER_RATE_EVIDENCE);
    let values: Vec<_> = cache.supporting_frames(source, &[1, 2, 3]).map(|p| p.no).collect();
    assert_eq!(values, [3]);

    let mut oversized = crate::net::parser::parse_ethernet(&[0; 14], 999, 3.0);
    oversized.bytes.resize(MAX_CONTROL_PLANE_EVIDENCE_BYTES + 1, 0);
    cache.remember(source, &oversized);
    assert!(cache.0.is_empty());
}
