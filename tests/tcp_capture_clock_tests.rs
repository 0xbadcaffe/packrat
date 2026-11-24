#[path = "support/packets.rs"]
mod packets;

use packrat_tui::engine::AnalysisCore;
use packrat_tui::net::packet::{CaptureMetadata, CaptureTimestamp, Packet, TimestampResolution};
use packrat_tui::net::parser::parse_ethernet;

fn observed(mut packet: Packet, at: f64, (section_id, interface_id): (u32, u32)) -> Packet {
    packet.timestamp = at;
    let length = packet.bytes.len() as u32;
    packet.capture = Some(CaptureMetadata {
        timestamp: Some(CaptureTimestamp {
            ticks: at as u64,
            resolution: TimestampResolution::Decimal(0),
            offset_seconds: 0,
        }),
        captured_length: length,
        wire_length: length,
        link_type: 1,
        section_id,
        interface_id,
        interface_name: None,
        comments: Vec::new(),
    });
    packet
}

fn clock_marker(frame: u64, path: (u32, u32)) -> Packet {
    let mut other = packets::tcp(frame, 9000, 0x10, b"").bytes;
    other[36..38].copy_from_slice(&81_u16.to_be_bytes());
    observed(parse_ethernet(&other, frame, 400.0), 400.0, path)
}

#[test]
fn reset_and_overlap_evidence_age_only_on_their_capture_clock() {
    let short_lived_path = (0, 0);
    for (rule, first, later) in [
        ("tcp.payload_after_observed_reset", packets::tcp(1, 100, 0x04, b""), packets::tcp(3, 101, 0x18, b"new")),
        ("tcp.conflicting_retransmission", packets::tcp(1, 100, 0x18, b"abc"), packets::tcp(3, 100, 0x18, b"xbc")),
    ] {
        for marker_path in [(0, 0), (0, 1), (1, 0)] {
            let mut core = AnalysisCore::default();
            core.analyze(&observed(first.clone(), 10.0, short_lived_path));
            core.analyze(&clock_marker(2, marker_path));
            core.analyze(&observed(later.clone(), 20.0, short_lived_path));
            let matches: Vec<_> = core.alert_center.items.iter().filter(|alert| {
                alert.provenance.as_ref().is_some_and(|provenance| provenance.rule_id == rule)
            }).collect();
            let expected = usize::from(marker_path != short_lived_path);
            assert_eq!(matches.len(), expected, "{rule}, marker on {marker_path:?}");
            if expected == 1 {
                assert_eq!(matches[0].packet_refs, [1, 3]);
            }
        }
    }
}

#[test]
fn repeated_tcp_bytes_do_not_become_periodic_when_another_clock_advances() {
    let mut core = AnalysisCore::default();
    for index in 0..7 {
        let frame = index * 2 + 1;
        core.analyze(&observed(packets::tcp(frame, 100, 0x18, &[1; 12]), 10.0 + index as f64 * 10.0, (0, 0)));
        core.analyze(&clock_marker(frame + 1, (0, 1)));
    }
    assert!(!core.alert_center.items.iter().any(|alert| {
        alert.provenance.as_ref().is_some_and(|provenance| provenance.rule_id == "traffic.periodic_fixed_size")
    }));
}
