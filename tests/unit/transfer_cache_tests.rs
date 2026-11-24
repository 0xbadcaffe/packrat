use super::*;

fn key(port: usize) -> ExfilKey {
    ExfilKey {
        internal: "10.0.0.1".into(),
        external: "198.51.100.1".into(),
        destination_port: u16::try_from(port).unwrap(),
        transport: TransferTransport::Tcp,
        scope: ((None, None, None), [0; 2]),
    }
}

#[test]
fn transfer_cache_evicts_the_same_key_when_timestamps_tie() {
    for index in 0..8 {
        let mut states: HashMap<_, _> = (1..=MAX_SCAN_STATES)
            .map(|port| (port + index) % MAX_SCAN_STATES + 1)
            .map(|port| (key(port), ExfilState { last_seen: 30.0, ..Default::default() }))
            .collect();
        assert!(admit_exfil_history(&mut states, 30.0));
        assert!(!states.contains_key(&key(1)));
        assert!(states.contains_key(&key(2)));
        assert_eq!(states.len(), MAX_SCAN_STATES - 1);
    }
}

#[test]
fn late_transfer_does_not_evict_a_newer_history_from_a_full_cache() {
    let mut states: HashMap<_, _> = (1..=MAX_SCAN_STATES)
        .map(|port| (key(port), ExfilState {
            last_seen: if port == 2 { 30.0 } else { 60.0 },
            ..Default::default()
        }))
        .collect();
    assert!(!admit_exfil_history(&mut states, 29.0));
    assert_eq!(states.len(), MAX_SCAN_STATES);
    assert!(states.contains_key(&key(2)));
    assert!(admit_exfil_history(&mut states, 31.0));
    assert!(!states.contains_key(&key(2)));
    assert!(states.contains_key(&key(1)));
    assert!(admit_exfil_history(&mut states, 1.0));
    assert_eq!(states.len(), MAX_SCAN_STATES - 1);
}
