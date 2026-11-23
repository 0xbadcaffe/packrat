use super::*;

#[test]
fn periodic_candidates_respect_frame_and_direction_byte_budgets() {
    let mut window = BeaconDirection::default();
    window.samples.push(BeaconSample { timestamp: 1.0, size: 1400, packet_no: 1 });
    for no in 1..=32 {
        let mut pkt = crate::net::parser::parse_ethernet(&[0; 14], no, no as f64);
        pkt.bytes.resize(1400, 0);
        window.remember(&pkt);
    }
    assert_eq!(window.retained.back().unwrap().0.no, 32);
    assert!(window.retained.front().unwrap().0.no > 1);
    assert!(window.retained_cost <= MAX_PERIODIC_DIRECTION_COST);

    let mut pkt = crate::net::parser::parse_ethernet(&[0; 14], 33, 33.0);
    pkt.bytes.resize(MAX_PERIODIC_FRAME_COST + 1, 0);
    window.samples[0].timestamp = 31.0;
    window.remember(&pkt);
    assert_eq!(window.retained.front().unwrap().0.no, 31);
    assert_eq!(window.retained.back().unwrap().0.no, 32);

    pkt.bytes.truncate(14);
    window.remember(&pkt);
    assert_eq!(window.retained.iter().map(|(packet, _)| packet.no).collect::<Vec<_>>(), [31, 32, 33]);
    assert_eq!(window.retained_cost, window.retained.iter().map(|(_, cost)| cost).sum::<usize>());
}
