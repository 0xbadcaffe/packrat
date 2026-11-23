#[path = "support/packets.rs"]
mod packets;

use packrat_tui::{
    engine::AnalysisCore,
    net::{flow::FlowKey, packet::Packet, parser::parse_ethernet},
};

fn observation(no: u64, flags: u8, destination: u8, timestamp: f64) -> Packet {
    let mut packet = packets::tcp(no, no as u32, flags, b"");
    packet.bytes[33] = destination;
    parse_ethernet(&packet.bytes, no, timestamp)
}

#[test]
fn flow_badges_do_not_infer_scans_or_syn_spikes_from_ordinary_ack_traffic() {
    let mut core = AnalysisCore::default();
    for no in 1..=55 {
        core.analyze(&observation(no, 0x10, 2, no as f64 / 1000.));
    }
    for (no, destination) in (56..).zip(3..=9) {
        core.analyze(&observation(no, 0x10, destination, no as f64 / 1000.));
    }
    assert_eq!(core.flow_tracker.flows.len(), 8);
    assert!(
        core.flow_tracker
            .flows
            .values()
            .all(|flow| !flow.flags.scan && !flow.flags.tcp_anomaly)
    );
}

#[test]
fn scan_badge_identifies_the_detector_trigger_flow_not_all_host_traffic() {
    let mut core = AnalysisCore::default();
    let mut trigger = None;
    for no in 1..=12 {
        let packet = observation(no, 0x02, no as u8 + 10, no as f64 / 10.);
        core.analyze(&packet);
        if no == 12 {
            trigger = Some(FlowKey::from_packet(&packet));
        }
    }
    let alert = core
        .alert_center
        .items
        .iter()
        .find(|alert| alert.title == "Horizontal host scan")
        .unwrap();
    assert_eq!(alert.packet_no, 12);
    let actual: Vec<_> = core
        .flow_tracker
        .flows
        .values()
        .filter(|flow| flow.flags.scan)
        .map(|flow| &flow.key)
        .collect();
    assert_eq!(actual, [trigger.as_ref().unwrap()]);
}

#[test]
fn syn_spike_badge_and_saved_tuple_come_from_the_same_finding() {
    let mut core = AnalysisCore::default();
    let last = observation(100, 0x02, 2, 0.1);
    for no in 1..100 {
        core.analyze(&observation(no, 0x02, 2, no as f64 / 1000.));
    }
    let flow = FlowKey::from_packet(&last);
    assert!(!core.flow_tracker.flows[&flow].flags.tcp_anomaly);
    core.analyze(&last);
    let alert = core
        .alert_center
        .items
        .iter()
        .find(|alert| alert.title == "SYN arrival spike")
        .unwrap();
    assert_eq!(alert.packet_no, last.no);
    assert_eq!(
        alert.flow.unwrap().destination,
        "10.0.0.2:80".parse().unwrap()
    );
    assert!(core.flow_tracker.flows[&flow].flags.tcp_anomaly);
}
