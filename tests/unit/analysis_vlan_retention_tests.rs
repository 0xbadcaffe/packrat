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
        core.analyze(&frame(i as u64, 20, Some(i as u16 + 1000)));
        assert_eq!(core.alert_center.drain_pending_exports().len(), 1);
    }
    let no = MAX_RECENT_VLAN_ALERTS as u64 + 1;
    core.analyze(&frame(no, 1, Some(no as u16)));
    let new = core.alert_center.drain_pending_exports();
    assert_eq!(new.len(), 2);
    assert!(new.iter().all(|alert| alert.packet_refs == [no]));
    assert!(new.iter().any(|alert| alert.title == "Stacked VLAN tags"));
    assert!(new.iter().any(|alert| alert.title == VLAN_ID_ONE));
    assert_eq!(core.vlan_intel.alerts.len(), MAX_RECENT_VLAN_ALERTS);
    assert_eq!(core.vlan_intel.alerts.front().unwrap().pkt_no, 3);
    assert_eq!(core.vlan_intel.alerts.back().unwrap().pkt_no, no);
}

#[test]
fn vlan_markings_use_scoped_wire_evidence_without_inferring_port_policy() {
    use crate::analysis::alert_provenance::EvidenceConfidence;
    use crate::net::packet::{CaptureMetadata, CaptureTimestamp, TimestampResolution};

    let capture = |packet: &Packet, interface_id, link_type| CaptureMetadata {
        timestamp: Some(CaptureTimestamp {
            ticks: packet.no,
            resolution: TimestampResolution::Decimal(0),
            offset_seconds: 0,
        }),
        captured_length: packet.bytes.len() as u32,
        wire_length: packet.bytes.len() as u32,
        link_type, interface_id, section_id: 0, interface_name: None, comments: Vec::new(),
    };
    let mut core = crate::engine::AnalysisCore::default();
    let mut stale = frame(1, 20, None);
    stale.vlan_id = Some(1);
    stale.vlan_pcp = Some(7);
    core.analyze(&stale);
    let mut truncated = frame(2, 1, None);
    truncated.bytes[14] = 0xe0;
    truncated.bytes.truncate(16);
    core.analyze(&truncated);
    let mut unsupported = frame(3, 1, None);
    unsupported.capture = Some(capture(&unsupported, 0, 113));
    assert_eq!(core.vlan_intel.ingest(&unsupported), 0);
    assert!(core.alert_center.items.is_empty());

    for (no, iface) in [(4, 2), (5, 2), (6, 3)] {
        let mut tagged = frame(no, 1, Some(200));
        tagged.bytes[14] |= 0xe0;
        tagged.capture = Some(capture(&tagged, iface, 1));
        core.analyze(&tagged);
    }
    let mut priority_only = frame(7, 0, None);
    priority_only.bytes[14] = 0xe0;
    core.analyze(&priority_only);

    for (id, title, role, citations) in [
        ("vlan.vid_one_observed", VLAN_ID_ONE, "inner tag 0x8100, VID 1", &[4, 6][..]),
        ("vlan.pcp_seven_observed", VLAN_PCP_SEVEN, "outer tag 0x88a8, VID 200", &[4, 6, 7][..]),
    ] {
        let alerts = core.alert_center.items.iter().filter(|alert| alert.title == title);
        assert_eq!(alerts.clone().map(|alert| alert.packet_no).collect::<Vec<_>>(), citations);
        for alert in alerts {
            assert_eq!(alert.packet_refs, [alert.packet_no]);
            assert_eq!(alert.severity, "INFO");
            let provenance = alert.provenance.as_ref().unwrap();
            assert_eq!(provenance.rule_id, id);
            assert_eq!(provenance.confidence, EvidenceConfidence::DirectObservation);
            assert!(alert.detail.contains(if alert.packet_no == 7 { "single tag 0x8100, VID 0" } else { role }));
            assert!(alert.detail.contains("unverified"));
        }
    }
    assert!(core.incidents.incidents.is_empty());
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
