use super::*;

#[test]
fn evidence_lookup_requires_the_observed_tag_path_even_for_an_exact_frame_number() {
    let make = |no, tpid: u16, tci: u16, marker| {
        let mut raw = vec![0; 12];
        raw.extend([tpid, tci, 0x88b5].into_iter().flat_map(u16::to_be_bytes));
        raw.push(marker);
        crate::net::parser::parse_ethernet(&raw, no, no as f64)
    };
    let first = make(1, 0x8100, 20, 1);
    let second = make(1, 0x88a8, 20, 2);
    let trigger = make(2, 0x8100, 0xb014, 3);
    let other_trigger = make(2, 0x88a8, 0xb014, 4);
    assert_eq!(first.vlan_id, Some(20));
    assert_eq!(other_trigger.vlan_id, first.vlan_id);
    let mut evidence = RecentEvidence::<8, 60>::default();
    evidence.remember(&first);
    assert!(evidence.cited_packet(&other_trigger, 1).is_none());
    evidence.remember(&second);
    assert_eq!(evidence.supporting_packet(&trigger, 1).unwrap().bytes, first.bytes);
    assert_eq!(evidence.supporting_packet(&other_trigger, 1).unwrap().bytes, second.bytes);
}

fn captured(frame: u64, timestamp: f64, section_id: u32, interface_id: u32) -> Packet {
    let mut packet = crate::net::parser::parse_ethernet(&[0; 14], frame, timestamp);
    packet.capture = Some(crate::net::packet::CaptureMetadata {
        timestamp: None,
        captured_length: 14,
        wire_length: 14,
        link_type: 1,
        section_id,
        interface_id,
        interface_name: None,
        comments: Vec::new(),
    });
    packet
}

#[test]
fn earlier_bytes_survive_unrelated_section_and_interface_clocks() {
    let mut cache = RecentEvidence::<8, 60>::default();
    cache.remember(&captured(1, 10.0, 0, 0));
    cache.remember(&captured(2, 400.0, 0, 1));
    cache.remember(&captured(3, 600.0, 1, 0));
    let trigger = captured(4, 70.0, 0, 0);
    cache.remember(&trigger);
    assert_eq!(cache.supporting_packet(&trigger, 1).unwrap().no, 1);

    let after_limit = captured(5, 70.001, 0, 0);
    cache.remember(&after_limit);
    assert!(cache.cited_packet(&after_limit, 1).is_none());
    assert!(cache.cited_packet(&captured(6, 402.0, 0, 1), 2).is_some());
    assert!(cache.cited_packet(&captured(7, 602.0, 1, 0), 3).is_some());
}

#[test]
fn expired_out_of_order_evidence_cannot_displace_a_live_entry() {
    let mut cache = RecentEvidence::<3, 60>::default();
    cache.remember(&captured(1, 120.0, 0, 0));
    cache.remember(&captured(2, 110.0, 0, 1));
    cache.remember(&captured(3, 60.0, 0, 0));
    let trigger = captured(4, 130.0, 0, 0);
    cache.remember(&trigger);
    assert!(cache.cited_packet(&trigger, 1).is_some());
    assert!(cache.cited_packet(&captured(5, 132.0, 0, 1), 2).is_some());
    assert!(cache.cited_packet(&trigger, 3).is_none());
}

#[test]
fn full_cache_evicts_oldest_arrival_and_never_keeps_stale_index_entries() {
    let mut cache = RecentEvidence::<2, 60>::default();
    for frame in 1..=12 {
        cache.remember(&captured(frame, 100.0, 0, 1));
    }
    cache.remember(&captured(13, 10.0, 0, 0));
    cache.remember(&captured(14, 20.0, 0, 0));
    assert!(cache.cited_packet(&captured(15, 100.0, 0, 1), 12).is_none());
    assert!(cache.supporting_packet(&captured(16, 22.0, 0, 0), 13).is_some());
    assert!(cache.supporting_packet(&captured(17, 23.0, 0, 0), 14).is_some());
    assert_eq!(cache.packets.len(), 2);
    assert_eq!(cache.order.len(), 2);
    assert_eq!(cache.by_age.len(), 2);
}
