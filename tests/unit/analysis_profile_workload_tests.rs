use super::*;

#[test]
fn workload_is_finite_and_uses_bounded_packet_retention() {
    let summary = run(10_250);
    assert_eq!(summary.packets, 10_250);
    assert_eq!(summary.retained_packets, 10_000);
    assert_eq!(summary.first_retained_packet, Some(251));
    assert_eq!(summary.selected_packet, Some(251));
    assert!(summary.alerts <= 2_000);
}
