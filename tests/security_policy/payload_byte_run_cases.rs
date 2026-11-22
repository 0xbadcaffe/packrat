use super::ipv4_tcp_packet;
use packrat_tui::{engine::AnalysisCore, net::parser::parse_ethernet};

#[test]
fn nop_like_pattern_ignores_headers_padding_and_runs_below_threshold() {
    const TITLE: &str = "Repeated NOP-like byte pattern";
    let mut core = AnalysisCore::default();
    let mut header = ipv4_tcp_packet(1, 100, 0x18, b"data").bytes;
    header.splice(34..34, [0x90; 16]);
    header[14] = 0x49;
    let total_length = (header.len() - 14) as u16;
    header[16..18].copy_from_slice(&total_length.to_be_bytes());
    core.analyze(&parse_ethernet(&header, 1, 1.0));

    let mut padding = ipv4_tcp_packet(2, 104, 0x18, b"data").bytes;
    padding.extend([0x90; 16]);
    core.analyze(&parse_ethernet(&padding, 2, 2.0));
    core.analyze(&ipv4_tcp_packet(3, 108, 0x18, &[0x90; 15]));
    assert!(
        core.alert_center
            .items
            .iter()
            .all(|alert| alert.title != TITLE)
    );

    core.analyze(&ipv4_tcp_packet(4, 123, 0x18, &[0x90; 16]));
    let alert = core
        .alert_center
        .items
        .iter()
        .find(|alert| alert.title == TITLE)
        .unwrap();
    assert_eq!(alert.severity, "LOW");
    assert_eq!(alert.packet_refs, [4]);
    assert_eq!(
        alert.provenance.as_ref().unwrap().rule_id,
        "payload.nop_like_byte_run"
    );
    assert!(alert.detail.contains("execution are unverified"));
    assert!(core.incidents.incidents.is_empty());
}
