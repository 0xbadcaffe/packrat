use super::*;

#[test]
fn auth_retry_history_is_bounded_and_duplicates_do_not_extend_it() {
    let mut history = AuthRetryHistory::default();
    for sequence in 0..=MAX_AUTH_RETRY_TOKENS as u32 {
        assert!(history.remember(1.0, 1.0, (40_000, sequence)));
    }
    assert_eq!(history.0.len(), MAX_AUTH_RETRY_TOKENS);
    assert!(history.0.iter().all(|(_, token)| token.1 != 0));
    let token = (40_000, 64);
    assert!(!history.remember(61.0, 61.0, token));
    assert!(history.remember(62.0, 62.0, token));
    assert_eq!(history.0, [(62.0, token)]);
}

#[test]
fn delayed_tokens_do_not_displace_newer_retry_evidence_at_capacity() {
    let mut history = AuthRetryHistory::default();
    for sequence in 0..MAX_AUTH_RETRY_TOKENS as u32 {
        assert!(history.remember(10.0, 10.0, (40_000, sequence)));
    }
    let delayed = (40_000, MAX_AUTH_RETRY_TOKENS as u32);
    assert!(!history.remember(9.0, 10.0, delayed));
    assert_eq!(history.0.len(), MAX_AUTH_RETRY_TOKENS);
    assert!(!history.remember(11.0, 11.0, (40_000, 0)));
    assert!(history.remember(11.0, 11.0, delayed));
    assert!(history.0.iter().any(|&(_, token)| token == delayed));
}

#[test]
fn auth_window_capacity_preserves_newer_history_and_breaks_timestamp_ties_by_key() {
    for offset in [0, 1, 17, MAX_ENTRIES - 1] {
        let mut engine = SecurityEngine::default();
        let mut observation = crate::net::parser::parse_ethernet(&[], 1, 10.0);
        observation.src = "192.0.2.10".into();
        observation.dst = "192.0.2.20".into();
        let record = |engine: &mut SecurityEngine, packet: &Packet, port| {
            engine.record_service_observation(packet, "FTP", true, port, (40_000, 1), Vec::new(), None);
        };
        for index in 0..MAX_ENTRIES {
            record(&mut engine, &observation, ((index + offset) % MAX_ENTRIES + 1) as u16);
        }
        let added = (MAX_ENTRIES + 1) as u16;
        observation.timestamp = 9.0;
        record(&mut engine, &observation, added);
        assert_eq!(engine.bf_windows.len(), MAX_ENTRIES);
        assert!(!engine.bf_windows.keys().any(|key| key.port == added));

        observation.timestamp = 10.0;
        record(&mut engine, &observation, added);
        let ports: std::collections::BTreeSet<_> = engine.bf_windows.keys().map(|key| key.port).collect();
        assert_eq!(ports, (2..=added).collect());
    }
}
