use super::*;

#[test]
fn fragment_evidence_retention_respects_byte_budget_and_deduplicates() {
    let mut state = FragmentState {
        retained_bytes: MAX_FRAGMENT_EVIDENCE_BYTES - 3,
        ..Default::default()
    };
    state.remember(1, 0, b"ab");
    state.remember(2, 0, b"ab");
    state.remember(3, 8, b"cd");
    state.remember(4, 8, b"e");
    assert_eq!(state.retained_bytes, MAX_FRAGMENT_EVIDENCE_BYTES);
    assert_eq!(
        state
            .slices
            .iter()
            .map(|slice| slice.packet_no)
            .collect::<Vec<_>>(),
        [1, 4]
    );
}

#[test]
fn fragment_evidence_retention_caps_sample_count() {
    let mut state = FragmentState::default();
    for i in 0..MAX_FRAGMENTS_PER_DATAGRAM + 1 {
        state.remember(i as u64 + 1, i as u32 * 8, b"abcdefghi");
    }
    assert_eq!(state.slices.len(), MAX_FRAGMENTS_PER_DATAGRAM);
    assert_eq!(state.retained_bytes, MAX_FRAGMENTS_PER_DATAGRAM * 9);
}

#[test]
fn tcp_payload_history_rolls_by_bytes_and_frames() {
    let mut history = TcpPayloadHistory::default();
    let large = vec![0; 40_000];
    history.remember_distinct(1, 100, &large);
    history.remember_distinct(2, 100_000, &large);
    assert!(!history.contains(100, &large));
    assert!(history.contains(100_000, &large));
    assert_eq!(history.bytes, large.len());

    history.clear();
    for i in 0..=MAX_TCP_SLICES_PER_DIRECTION {
        history.remember_distinct(i as u64 + 1, i as u32 * 8, b"sample");
    }
    assert_eq!(history.slices.len(), MAX_TCP_SLICES_PER_DIRECTION);
    assert_eq!(history.bytes, MAX_TCP_SLICES_PER_DIRECTION * 6);
    assert_eq!(history.slices.front().unwrap().packet_no, 2);
    assert_eq!(history.slices.back().unwrap().packet_no, MAX_TCP_SLICES_PER_DIRECTION as u64 + 1);
}
