use super::ipv4_fragment_packet;
use packrat_tui::engine::AnalysisCore;

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
    assert_eq!(alert.provenance.as_ref().unwrap().revision, 2);
    assert!(alert.detail.contains("resource impact unverified"));
}
