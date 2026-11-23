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
