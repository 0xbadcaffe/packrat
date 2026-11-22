use super::*;

fn frame(no: u64, inner: u16, outer: Option<u16>) -> Packet {
    let mut raw = vec![0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 7];
    if let Some(outer) = outer {
        raw.extend_from_slice(&0x88a8_u16.to_be_bytes());
        raw.extend_from_slice(&outer.to_be_bytes());
    }
    raw.extend_from_slice(&0x8100_u16.to_be_bytes());
    raw.extend_from_slice(&inner.to_be_bytes());
    raw.extend_from_slice(&0x88b5_u16.to_be_bytes());
    let mut packet = crate::net::parser::parse_ethernet(&raw, no, no as f64);
    packet.vlan_id = Some(inner);
    packet.outer_vlan_id = outer;
    packet
}

#[test]
fn new_vlan_findings_reach_alert_center_when_display_history_rolls_over() {
    let mut core = crate::engine::AnalysisCore::default();
    for i in 1..=MAX_RECENT_VLAN_ALERTS {
        core.analyze(&frame(i as u64, 20, Some(i as u16)));
        assert_eq!(core.alert_center.drain_pending_exports().len(), 1);
    }
    let no = MAX_RECENT_VLAN_ALERTS as u64 + 1;
    core.analyze(&frame(no, 1, Some(no as u16)));
    let new = core.alert_center.drain_pending_exports();
    assert_eq!(new.len(), 2);
    assert!(new.iter().all(|alert| alert.packet_refs == [no]));
    assert!(new.iter().any(|alert| alert.title == "Stacked VLAN tags"));
    assert!(new.iter().any(|alert| alert.title == "Native-VLAN"));
    assert_eq!(core.vlan_intel.alerts.len(), MAX_RECENT_VLAN_ALERTS);
    assert_eq!(core.vlan_intel.alerts.front().unwrap().pkt_no, 3);
    assert_eq!(core.vlan_intel.alerts.back().unwrap().pkt_no, no);
}

#[test]
fn vlan_dedup_evicts_the_oldest_key_and_retains_recent_suppression() {
    let mut intel = VlanIntel::default();
    for i in 0..MAX_VLAN_DEDUP_KEYS {
        assert!(intel.allow_alert(format!("key-{i}"), 1));
    }
    assert!(!intel.allow_alert("key-0".into(), 2));
    assert!(intel.allow_alert("new".into(), 2));
    assert_eq!(intel.dedup.len(), MAX_VLAN_DEDUP_KEYS);
    assert_eq!(intel.dedup_order.len(), MAX_VLAN_DEDUP_KEYS);
    assert!(!intel.allow_alert("new".into(), 3));
    assert!(intel.allow_alert("key-0".into(), 3));
    intel.clear();
    assert!(intel.dedup.is_empty() && intel.dedup_order.is_empty());
}

#[test]
fn vlan_host_counts_are_bounded_without_stopping_packet_and_byte_totals() {
    let mut intel = VlanIntel::default();
    let mut no = 0;
    for vlan in 2..=130 {
        for sample in 0..=MAX_HOST_SAMPLES_PER_VLAN {
            no += 1;
            let mut packet = frame(no, vlan, None);
            packet.src = format!("host-{sample}");
            intel.ingest(&packet);
        }
    }
    let first = &intel.stats[&2];
    assert_eq!(first.hosts.len(), MAX_HOST_SAMPLES_PER_VLAN);
    assert!(first.host_samples_limited);
    assert_eq!(first.packets, MAX_HOST_SAMPLES_PER_VLAN as u64 + 1);
    assert_eq!(first.bytes, first.packets * u64::from(frame(1, 2, None).length));
    assert_eq!(intel.host_samples, MAX_HOST_SAMPLES);
    let last = &intel.stats[&130];
    assert!(last.hosts.is_empty() && last.host_samples_limited);
    intel.clear();
    assert_eq!(intel.host_samples, 0);
    assert!(intel.stats.is_empty());
}
