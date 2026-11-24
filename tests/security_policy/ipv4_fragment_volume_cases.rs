use super::ipv4_fragment_packet;
use packrat_tui::engine::AnalysisCore;

#[test]
fn ipv4_fragment_path_controls_overlap_and_distinct_offset_evidence() {
    let packet = |no, id, offset, tpid: u16, payload| {
        let mut raw = ipv4_fragment_packet(no, id, offset, true, payload).bytes;
        raw.splice(12..12, [tpid, 20].into_iter().flat_map(u16::to_be_bytes));
        packrat_tui::net::parser::parse_ethernet(&raw, no, no as f64 / 10.0)
    };
    let mut core = AnalysisCore::default();
    core.analyze(&packet(1, 7, 0, 0x8100, b"12345678"));
    core.analyze(&packet(2, 7, 0, 0x88a8, b"abcdefgh"));
    assert!(core.alert_center.items.is_empty());
    core.analyze(&packet(3, 7, 0, 0x8100, b"abcdefgh"));
    let conflict = core.alert_center.items.iter().find(|item| item.title == "Conflicting IPv4 fragments").unwrap();
    assert_eq!(conflict.packet_refs, [1, 3]);

    let mut core = AnalysisCore::default();
    for index in 0..=64_u16 {
        let tpid = if index % 2 == 0 { 0x8100 } else { 0x88a8 };
        core.analyze(&packet(u64::from(index) + 1, 8, index * 8, tpid, b"12345678"));
    }
    assert!(core.alert_center.items.iter().all(|item| item.title != "IPv4 fragment flood"));
    for index in 65..=96_u16 {
        core.analyze(&packet(u64::from(index) + 1, 8, index * 8, 0x8100, b"12345678"));
    }
    let burst = core.alert_center.items.iter().find(|item| item.title == "IPv4 fragment flood").unwrap();
    let expected = (1..=65).step_by(2).chain(66..=97).collect::<Vec<_>>();
    assert_eq!(burst.packet_refs, expected);
}

#[test]
fn ipv4_fragment_volume_counts_distinct_complete_offsets_and_keeps_evidence() {
    const TITLE: &str = "IPv4 fragment flood";
    let mut core = AnalysisCore::default();
    for index in 0..65 {
        core.analyze(&ipv4_fragment_packet(index + 1, 77, 0, true, b"12345678"));
    }
    for index in 0..65 {
        let mut truncated =
            ipv4_fragment_packet(index + 101, 88, index as u16 * 8, true, b"12345678");
        truncated.bytes.pop();
        core.analyze(&truncated);
    }
    assert!(
        core.alert_center
            .items
            .iter()
            .all(|alert| alert.title != TITLE)
    );

    for index in 0..66 {
        core.analyze(&ipv4_fragment_packet(
            index + 201,
            99,
            index as u16 * 8,
            true,
            b"12345678",
        ));
    }
    let alerts: Vec<_> = core
        .alert_center
        .items
        .iter()
        .filter(|alert| alert.title == TITLE)
        .collect();
    assert_eq!(alerts.len(), 1);
    let alert = alerts[0];
    assert_eq!(alert.severity, "MEDIUM");
    assert_eq!(alert.packet_no, 265);
    assert_eq!(alert.packet_refs, (201..=265).collect::<Vec<_>>());
    assert_eq!(alert.provenance.as_ref().unwrap().revision, 4);
    assert!(alert.detail.contains("resource impact unverified"));
}
