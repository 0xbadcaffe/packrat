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
