use super::*;

#[test]
fn administrative_reply_pairs_require_a_timely_preceding_frame() {
    let mut pending = PendingSyn::new(SynSample { at: 1.0, frame: 10 });
    pending.retry(SynSample { at: 10.0, frame: 20 });
    assert_eq!(pending.matched_frame(16.0, 21), Some(10));
    assert_eq!(pending.matched_frame(17.0, 21), Some(20));
    assert_eq!(pending.matched_frame(17.0, 20), None);
    assert_eq!(pending.matched_frame(1.0, 9), None);
    assert_eq!(pending.matched_frame(1.0, 11), Some(10));
    assert_eq!(pending.matched_frame(26.0, 21), None);

    pending.retry(SynSample { at: 26.0, frame: 22 });
    pending.retry(SynSample { at: 27.0, frame: 19 });
    pending.retry(SynSample { at: 24.0, frame: 23 });
    assert_eq!(pending.matched_frame(25.0, 24), None);
    assert_eq!(pending.matched_frame(26.0, 24), Some(22));
}
