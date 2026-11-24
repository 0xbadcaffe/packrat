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
            ticks: (at * 1000.0) as u64,
            resolution: TimestampResolution::Decimal(3),
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

fn tcp_on_port(frame: u64, port: u16, flags: u8, payload: &[u8], at: f64, path: (u32, u32)) -> Packet {
    let mut wire = packets::tcp(frame, 100, flags, payload).bytes;
    wire[34..36].copy_from_slice(&port.to_be_bytes());
    observed(parse_ethernet(&wire, frame, at), at, path)
}

#[test]
fn tcp_capacity_evicts_by_observation_order_across_capture_clocks() {
    let mut core = AnalysisCore::default();
    let fast_path = (0, 1);
    let slow_path = (0, 0);
    core.analyze(&tcp_on_port(1, 30_000, 0x04, b"", 400.0, fast_path));
    for frame in 2..=511 {
        core.analyze(&tcp_on_port(frame, frame as u16 + 30_000, 0x10, b"", 400.0, fast_path));
    }
    core.analyze(&tcp_on_port(512, 40_000, 0x04, b"", 10.0, slow_path));
    core.analyze(&tcp_on_port(513, 50_000, 0x10, b"", 400.0, fast_path));
    core.analyze(&tcp_on_port(514, 40_000, 0x18, b"later", 20.0, slow_path));
    core.analyze(&tcp_on_port(515, 30_000, 0x18, b"later", 410.0, fast_path));

    let reset_refs: Vec<_> = core.alert_center.items.iter()
        .filter(|alert| alert.title == "TCP payload after reset")
        .map(|alert| alert.packet_refs.as_slice()).collect();
    assert_eq!(reset_refs, [&[512, 514][..]]);
}

#[test]
fn late_frame_refreshes_capacity_recency_without_changing_reset_time() {
    let mut core = AnalysisCore::default();
    let path = (0, 0);
    core.analyze(&tcp_on_port(1, 40_000, 0x04, b"", 20.0, path));
    for frame in 2..=512 {
        core.analyze(&tcp_on_port(frame, frame as u16 + 30_000, 0x10, b"", 30.0, path));
    }
    core.analyze(&tcp_on_port(513, 40_000, 0x10, b"", 19.0, path));
    core.analyze(&tcp_on_port(514, 50_000, 0x10, b"", 30.0, path));
    core.analyze(&tcp_on_port(515, 40_000, 0x18, b"older", 19.5, path));
    core.analyze(&tcp_on_port(516, 40_000, 0x18, b"later", 40.0, path));

    let reset_refs: Vec<_> = core.alert_center.items.iter()
        .filter(|alert| alert.title == "TCP payload after reset")
        .map(|alert| alert.packet_refs.as_slice()).collect();
    assert_eq!(reset_refs, [&[1, 516][..]]);
}
