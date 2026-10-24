use packrat_tui::net::packet::{CaptureMetadata, CaptureTimestamp, Packet, TimestampResolution};
use packrat_tui::net::parser::parse_ethernet;

#[test]
fn timestamps_preserve_original_clock_ticks_and_signed_offsets() {
    let time = CaptureTimestamp {
        ticks: 1_790_000_000_123_456_789,
        resolution: TimestampResolution::Decimal(9),
        offset_seconds: 0,
    };
    assert_eq!(time.nanoseconds(), 1_790_000_000_123_456_789);
    let binary = CaptureTimestamp {
        ticks: 1536,
        resolution: TimestampResolution::Binary(10),
        offset_seconds: -2,
    };
    assert_eq!(binary.nanoseconds(), -500_000_000);
    let fine = CaptureTimestamp {
        ticks: u64::MAX,
        resolution: TimestampResolution::Decimal(255),
        offset_seconds: 0,
    };
    assert_eq!(fine.nanoseconds(), 0);
}

#[test]
fn old_saved_packets_remain_readable_without_capture_metadata() {
    let packet = parse_ethernet(&[], 1, 1.0);
    let json = serde_json::to_string(&packet).unwrap();
    assert!(!json.contains("capture"));
    let restored: Packet = serde_json::from_str(&json).unwrap();
    assert!(restored.capture.is_none());
}

#[test]
fn classic_export_preserves_nanoseconds_and_wire_length() {
    let path =
        std::env::temp_dir().join(format!("packrat-metadata-{}.pcap", rand::random::<u64>()));
    let mut packet = parse_ethernet(&[0; 14], 1, 1.0);
    packet.capture = Some(CaptureMetadata {
        timestamp: Some(CaptureTimestamp {
            ticks: 1_790_000_000_123_456_789,
            resolution: TimestampResolution::Decimal(9),
            offset_seconds: 0,
        }),
        captured_length: 14,
        wire_length: 100,
        link_type: 1,
        interface_id: 0,
        section_id: 0,
        interface_name: None,
        comments: Vec::new(),
    });
    let mut writer = packrat_tui::export::PcapWriter::new(&path).unwrap();
    writer.write_packet(&packet).unwrap();
    writer.flush().unwrap();
    drop(writer);
    let restored = packrat_tui::pcap_replay::read_pcap(&path).unwrap();
    let capture = restored[0].capture.as_ref().unwrap();
    assert_eq!(
        capture.timestamp.unwrap().nanoseconds(),
        1_790_000_000_123_456_789
    );
    assert_eq!(capture.wire_length, 100);
    assert!(capture.truncated());
    std::fs::remove_file(path).unwrap();
}
