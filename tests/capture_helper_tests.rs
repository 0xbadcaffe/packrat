use packrat_tui::capture::helper::{decode_frame, write_frame, MAX_CAPTURE_FRAME};

#[test]
fn capture_helper_protocol_round_trips_timestamp_and_frame() {
    let mut encoded = Vec::new();
    write_frame(&mut encoded, 123_456, b"ethernet frame").unwrap();
    let (timestamp, frame) = decode_frame(&encoded).unwrap();
    assert_eq!(timestamp, 123_456);
    assert_eq!(frame, b"ethernet frame");
}

#[test]
fn capture_helper_protocol_rejects_truncation_and_oversize() {
    let mut truncated = Vec::new();
    truncated.extend_from_slice(&1_u64.to_be_bytes());
    truncated.extend_from_slice(&10_u32.to_be_bytes());
    truncated.extend_from_slice(b"short");
    assert!(decode_frame(&truncated).is_err());
    assert!(write_frame(Vec::new(), 0, &vec![0_u8; MAX_CAPTURE_FRAME + 1]).is_err());
}
