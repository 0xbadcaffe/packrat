use super::*;
use packrat_tui::net::packet::CaptureMetadata;

fn captured(mut packet: Packet, section: u32, interface: u32, timestamp: f64) -> Packet {
    packet.timestamp = timestamp;
    let length = packet.bytes.len() as u32;
    packet.capture = Some(CaptureMetadata {
        timestamp: None,
        captured_length: length,
        wire_length: length,
        link_type: 1,
        section_id: section,
        interface_id: interface,
        interface_name: None,
        comments: Vec::new(),
    });
    packet
}

#[rstest]
#[case(0, 0, [None, Some(10), Some(12)])]
#[case(0, 1, [Some(18), Some(6), Some(8)])]
#[case(1, 0, [Some(18), Some(6), Some(8)])]
fn behavior_history_expires_on_its_own_capture_interface(
    #[case] section: u32,
    #[case] interface: u32,
    #[case] expected: [Option<u64>; 3],
) {
    let mut engine = SecurityEngine::default();
    let payload: Vec<_> = (0..60_000).map(|index| (index * 73 % 256) as u8).collect();
    for frame in 1..=4 {
        engine.update(&captured(outbound_tcp(frame, &payload), 0, 0, frame as f64 * 10.0));
    }
    engine.update(&captured(outbound_tcp(5, &[]), section, interface, 4_000.0));
    let offset = if (section, interface) == (0, 0) { 4_000.0 } else { 0.0 };
    for frame in 6..=18 {
        engine.update(&captured(outbound_tcp(frame, &payload), 0, 0, offset + (frame - 1) as f64 * 10.0));
    }

    for (signature, trigger) in [
        "Large asymmetric outbound transfer",
        "High-entropy outbound transfer",
        "Periodic fixed-size traffic",
    ].into_iter().zip(expected) {
        let frames: Vec<_> = engine.ids_alerts.iter().filter(|a| a.signature == signature).map(|a| a.pkt_no).collect();
        assert_eq!(frames, trigger.into_iter().collect::<Vec<_>>(), "{signature}");
    }
}
