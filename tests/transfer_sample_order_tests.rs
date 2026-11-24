#[path = "support/packets.rs"]
mod packets;

use packrat_tui::{engine::AnalysisCore, net::parser::parse_ethernet};

#[test]
fn late_reverse_sample_does_not_displace_more_recent_paired_evidence() {
    let mut core = AnalysisCore::default();
    for no in 1..=9 {
        let mut bytes = packets::tcp(no, no as u32 * 60_000, 0x18, b"reverse data").bytes;
        let client_port = if no == 1 { 40_000 } else { 41_000 + no as u16 };
        bytes[26..34].copy_from_slice(&[198, 51, 100, 10, 10, 0, 0, 5]);
        bytes[34..36].copy_from_slice(&80_u16.to_be_bytes());
        bytes[36..38].copy_from_slice(&client_port.to_be_bytes());
        let time = if no == 9 { 1.0 } else { 90.0 + no as f64 };
        core.analyze(&parse_ethernet(&bytes, no, time));
    }

    let payload = vec![0; 60_000];
    for no in 10..=26 {
        let mut bytes = packets::tcp(no, no as u32 * 60_000, 0x18, &payload).bytes;
        bytes[26..34].copy_from_slice(&[10, 0, 0, 5, 198, 51, 100, 10]);
        core.analyze(&parse_ethernet(&bytes, no, 100.0 + no as f64));
    }
    let alert = core.alert_center.items.iter()
        .find(|alert| alert.title == "Large asymmetric outbound transfer").unwrap();
    assert_eq!(alert.severity, "HIGH");
    assert_eq!(alert.packet_refs, (1..=8).chain(19..=26).collect::<Vec<_>>());
}
