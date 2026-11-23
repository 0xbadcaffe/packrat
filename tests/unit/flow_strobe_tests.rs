use super::{STROBE_MIN_PACKETS, VecDeque, observe_strobe};

#[test]
fn sustained_burst_uses_fixed_memory_and_expires_after_one_second() {
    let mut window = VecDeque::new();
    for count in 1..=50_000 {
        assert_eq!(
            observe_strobe(&mut window, 10.0),
            count >= STROBE_MIN_PACKETS
        );
    }
    assert_eq!(window.len(), STROBE_MIN_PACKETS);
    assert!(observe_strobe(&mut window, 11.0));
    assert!(!observe_strobe(&mut window, 11.001));
    assert_eq!(window, [11.0, 11.001]);
}

#[test]
fn reordered_observations_match_an_unbounded_high_water_window() {
    let mut window = VecDeque::new();
    let mut all = Vec::new();
    let mut newest = f64::NEG_INFINITY;
    for step in 0..5_000 {
        let round = f64::from(step / 250) * 2.0;
        let offset = f64::from((step * 127) % 250) / 200.0 - 0.2;
        let timestamp = round + offset;
        all.push(timestamp);
        newest = newest.max(timestamp);
        let count = all.iter().filter(|&&time| time >= newest - 1.0).count();
        assert_eq!(
            observe_strobe(&mut window, timestamp),
            count >= STROBE_MIN_PACKETS
        );
        assert_eq!(window.len(), count.min(STROBE_MIN_PACKETS));
    }
    let original = window.clone();
    let prior_flag = original.len() == STROBE_MIN_PACKETS;
    assert_eq!(observe_strobe(&mut window, f64::NAN), prior_flag);
    assert_eq!(window, original);
}
