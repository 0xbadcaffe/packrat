#[path = "support/packets.rs"]
mod packets;

use packrat_tui::net::{flow::FlowTracker, inspector::shannon_entropy};

#[test]
fn flow_entropy_keeps_the_exact_threshold_and_short_frame_behavior() {
    let varied: Vec<_> = (0..=255).collect();
    assert!(shannon_entropy(&varied[..147]) < 7.2);
    assert!(shannon_entropy(&varied[..148]) > 7.2);
    let mut tracker = FlowTracker::new();
    let mut packet = packets::tcp(1, 100, 0x18, b"");
    for (bytes, expected) in [
        (&varied[..148], true),
        (&varied[..20], true),
        (&varied[..147], false),
        (&varied[..256], true),
        (&[0; 256], false),
    ] {
        packet.bytes = bytes.to_vec();
        tracker.update(&packet);
        assert_eq!(tracker.iter().next().unwrap().flags.encrypted, expected);
    }
}
