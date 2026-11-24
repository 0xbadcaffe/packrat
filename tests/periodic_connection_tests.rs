#[path = "support/packets.rs"]
mod packets;

use packrat_tui::engine::AnalysisCore;

const RULE: &str = "traffic.periodic_fixed_size";

fn run(observations: &[(u64, u32, bool)]) -> Vec<(u64, Vec<u64>)> {
    let mut core = AnalysisCore::default();
    for (index, &(seconds, sequence, syn)) in observations.iter().enumerate() {
        let frame = index as u64 + 1;
        let (flags, payload) = if syn { (0x02, &[][..]) } else { (0x18, &[1; 12][..]) };
        let mut packet = packets::tcp(frame, sequence, flags, payload);
        packet.timestamp = seconds as f64;
        core.analyze(&packet);
    }
    core.alert_center.items.iter()
        .filter(|item| item.provenance.as_ref().is_some_and(|rule| rule.rule_id == RULE))
        .map(|item| (item.packet_no, item.packet_refs.clone()))
        .collect()
}

fn data(first_time: u64, first_sequence: u32, count: u32) -> impl Iterator<Item = (u64, u32, bool)> {
    (0..count).map(move |i| (first_time + u64::from(i) * 10, first_sequence + i * 12, false))
}

#[test]
fn short_connections_that_reuse_a_tuple_do_not_combine_periodic_evidence() {
    let observations: Vec<_> = [(1, 100, true)].into_iter()
        .chain(data(10, 101, 4))
        .chain([(45, 500, true)])
        .chain(data(50, 501, 3))
        .collect();
    assert!(run(&observations).is_empty());
}

#[test]
fn new_connection_on_the_same_tuple_can_open_a_separate_periodic_episode() {
    let observations: Vec<_> = [(1, 100, true)].into_iter()
        .chain(data(10, 101, 7))
        .chain([(75, 500, true)])
        .chain(data(80, 501, 7))
        .collect();
    assert_eq!(run(&observations), [(8, (2..=8).collect()), (16, (10..=16).collect())]);
}

#[test]
fn a_retransmitted_syn_does_not_clear_the_current_connection_samples() {
    let observations: Vec<_> = [(1, 100, true)].into_iter()
        .chain(data(10, 101, 3))
        .chain([(35, 100, true)])
        .chain(data(40, 137, 4))
        .collect();
    assert_eq!(run(&observations), [(9, vec![2, 3, 4, 6, 7, 8, 9])]);
}

#[test]
fn a_late_packet_that_predates_the_syn_cannot_seed_the_new_episode() {
    let observations: Vec<_> = [(1, 100, true), (15, 500, true), (10, 101, false)].into_iter()
        .chain(data(20, 501, 7))
        .collect();
    assert_eq!(run(&observations), [(10, (4..=10).collect())]);
}
