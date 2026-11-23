use super::{FlowKey, FlowSort, FlowTracker, NonZeroUsize, Packet};

fn packet(port: u16, timestamp: f64) -> Packet {
    Packet {
        capture: None,
        no: 1,
        timestamp,
        src: "192.0.2.10".into(),
        dst: "198.51.100.20".into(),
        protocol: "UDP".into(),
        length: 42,
        info: String::new(),
        src_port: Some(port),
        dst_port: Some(53),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes: Vec::new(),
    }
}

#[test]
fn retention_follows_packet_arrival_not_reads_or_capture_timestamps() {
    let mut tracker = FlowTracker::with_capacity(NonZeroUsize::new(2).unwrap());
    let a = packet(50001, 2.0);
    let b = packet(50002, 3.0);
    let c = packet(50003, 4.0);
    tracker.update(&a);
    tracker.update(&b);
    let old_a = packet(50001, 1.0);
    tracker.update(&old_a);
    assert_eq!(tracker.get(&FlowKey::from_packet(&b)).unwrap().packets, 1);
    tracker.update(&c);
    assert_eq!(tracker.len(), 2);
    assert_eq!(tracker.evicted(), 1);
    assert!(tracker.get(&FlowKey::from_packet(&b)).is_none());
    assert_eq!(tracker.get(&FlowKey::from_packet(&a)).unwrap().packets, 2);
    tracker.update(&b);
    assert!(tracker.get(&FlowKey::from_packet(&a)).is_none());
    assert_eq!(tracker.get(&FlowKey::from_packet(&b)).unwrap().packets, 1);
    assert_eq!(tracker.evicted(), 2);

    let tied = tracker.sorted_flows(&FlowSort::Packets);
    assert_eq!(tied[0].key, FlowKey::from_packet(&b));
    tracker.clear();
    assert!(tracker.is_empty());
    assert_eq!(tracker.evicted(), 0);
}

#[test]
fn retired_packet_does_not_inherit_a_new_summary_for_the_same_tuple() {
    let mut tracker = FlowTracker::with_capacity(NonZeroUsize::new(1).unwrap());
    let old = packet(50001, 1.0);
    let mut latest = packet(50001, 3.0);
    latest.no = 3;
    tracker.update(&old);
    assert!(tracker.get_for_packet(&old).is_some());
    tracker.update(&packet(50002, 2.0));
    tracker.update(&latest);
    assert!(tracker.get_for_packet(&old).is_none());
    assert_eq!(tracker.get_for_packet(&latest).unwrap().packets, 1);
    let mut pending = latest.clone();
    pending.no += 1;
    assert!(tracker.get_for_packet(&pending).is_none());
}
