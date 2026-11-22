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
