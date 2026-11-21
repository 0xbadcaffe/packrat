use super::*;
use packrat_tui::engine::AnalysisCore;

#[test]
fn syn_spike_evidence_excludes_retransmissions_and_other_vlan_scopes() {
    let mut core = AnalysisCore::default();
    for no in 1..=140 {
        let mut packet = tcp_probe(no, [10, 0, 0, 5], 443, 0x02, no as f64 / 1000.0);
        packet.bytes[38..42].copy_from_slice(&42_u32.to_be_bytes());
        packet.vlan_id = Some(10);
        core.analyze(&packet);
    }
    assert!(!core.alert_center.items.iter().any(|alert| alert.title == "SYN arrival spike"));

    for no in 141..=200 {
        let mut packet = tcp_probe(no, [10, 0, 0, 5], 443, 0x02, no as f64 / 1000.0);
        packet.vlan_id = Some(10);
        core.analyze(&packet);
        packet.vlan_id = Some(20);
        packet.no += 1000;
        core.analyze(&packet);
    }
    assert!(!core.alert_center.items.iter().any(|alert| alert.title == "SYN arrival spike"));

    for no in 201..=239 {
        let mut packet = tcp_probe(no, [10, 0, 0, 5], 443, 0x02, no as f64 / 1000.0);
        packet.vlan_id = Some(10);
        core.analyze(&packet);
    }
    let spikes: Vec<_> = core.alert_center.items.iter()
        .filter(|alert| alert.title == "SYN arrival spike").collect();
    assert_eq!(spikes.len(), 1);
    assert_eq!(spikes[0].packet_refs, std::iter::once(1).chain(141..=239).collect::<Vec<_>>());
    assert_eq!(spikes[0].provenance.as_ref().unwrap().rule_id, "tcp.syn_arrival_spike");
    assert_eq!(spikes[0].severity, "HIGH");
    assert!(spikes[0].detail.contains("service impact is unverified"));
    assert!(core.incidents.incidents.is_empty());
}
