use super::*;

#[test]
fn fragment_evidence_retention_respects_byte_budget_and_deduplicates() {
    let mut state = FragmentState {
        retained_bytes: MAX_FRAGMENT_EVIDENCE_BYTES - 3,
        ..Default::default()
    };
    state.remember(1, 0, b"ab");
    state.remember(2, 0, b"ab");
    state.remember(3, 8, b"cd");
    state.remember(4, 8, b"e");
    assert_eq!(state.retained_bytes, MAX_FRAGMENT_EVIDENCE_BYTES);
    assert_eq!(
        state
            .slices
            .iter()
            .map(|slice| slice.packet_no)
            .collect::<Vec<_>>(),
        [1, 4]
    );
}

#[test]
fn fragment_evidence_retention_caps_sample_count() {
    let mut state = FragmentState::default();
    for i in 0..MAX_FRAGMENTS_PER_DATAGRAM + 1 {
        state.remember(i as u64 + 1, i as u32 * 8, b"abcdefghi");
    }
    assert_eq!(state.slices.len(), MAX_FRAGMENTS_PER_DATAGRAM);
    assert_eq!(state.retained_bytes, MAX_FRAGMENTS_PER_DATAGRAM * 9);
}

fn fragment(
    frame: u64, identification: u16, offset: u16, timestamp: f64, path: (u32, u32),
) -> Packet {
    let mut wire = [0_u8; 42];
    wire[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    wire[14] = 0x45;
    wire[16..18].copy_from_slice(&28_u16.to_be_bytes());
    wire[18..20].copy_from_slice(&identification.to_be_bytes());
    let field = if offset == 0 { 0x2000 } else { offset / 8 };
    wire[20..22].copy_from_slice(&field.to_be_bytes());
    wire[23] = 17;
    wire[26..30].copy_from_slice(&[192, 0, 2, 1]);
    wire[30..34].copy_from_slice(&[192, 0, 2, 2]);
    let mut packet = crate::net::parser::parse_ethernet(&wire, frame, timestamp);
    packet.capture = Some(crate::net::packet::CaptureMetadata {
        timestamp: None,
        captured_length: wire.len() as u32,
        wire_length: wire.len() as u32,
        link_type: 1,
        section_id: path.0,
        interface_id: path.1,
        interface_name: None,
        comments: Vec::new(),
    });
    packet
}

fn fragment_key(packet: &Packet) -> (ScanScope, FragmentKey) {
    (scan_scope(packet), parse_ipv4_fragment(&packet.bytes).unwrap().key)
}

#[test]
fn fragment_history_expires_only_on_its_capture_clock() {
    for marker_path in [(0, 0), (0, 1), (1, 0)] {
        let mut engine = SecurityEngine::default();
        let original = fragment(1, 7, 0, -90.0, (0, 0));
        engine.check_ipv4_fragments(&original, None);
        engine.check_ipv4_fragments(&fragment(2, 8, 0, -20.0, marker_path), None);
        engine.check_ipv4_fragments(&fragment(3, 7, 8, -80.0, (0, 0)), None);
        let state = &engine.fragment_states[&fragment_key(&original)];
        let expected: &[(u32, u64)] = if marker_path == (0, 0) { &[(8, 3)] } else { &[(0, 1), (8, 3)] };
        assert_eq!(state.offset_frames, expected, "clock marker from {marker_path:?}");
    }
}

#[test]
fn fragment_capacity_keeps_recent_arrivals_on_the_slower_clock() {
    let mut engine = SecurityEngine::default();
    let oldest = fragment(1, 1, 0, 400.0, (0, 1));
    for id in 1..MAX_FRAGMENT_DATAGRAMS as u16 {
        engine.check_ipv4_fragments(&fragment(u64::from(id), id, 0, 400.0, (0, 1)), None);
    }
    let recent = fragment(600, 7, 0, 10.0, (0, 0));
    engine.check_ipv4_fragments(&recent, None);
    engine.check_ipv4_fragments(&fragment(601, 900, 0, 400.0, (0, 1)), None);
    assert_eq!(engine.fragment_states.len(), MAX_FRAGMENT_DATAGRAMS);
    assert!(engine.fragment_states.contains_key(&fragment_key(&recent)));
    assert!(!engine.fragment_states.contains_key(&fragment_key(&oldest)));
}

#[test]
fn tcp_payload_history_rolls_by_bytes_and_frames() {
    let mut history = TcpPayloadHistory::default();
    let large = vec![0; 40_000];
    history.remember_distinct(1, 100, &large);
    history.remember_distinct(2, 100_000, &large);
    assert!(!history.contains(100, &large));
    assert!(history.contains(100_000, &large));
    assert_eq!(history.bytes, large.len());

    let mut history = TcpPayloadHistory::default();
    for i in 0..=MAX_TCP_SLICES_PER_DIRECTION {
        history.remember_distinct(i as u64 + 1, i as u32 * 8, b"sample");
    }
    assert_eq!(history.slices.len(), MAX_TCP_SLICES_PER_DIRECTION);
    assert_eq!(history.bytes, MAX_TCP_SLICES_PER_DIRECTION * 6);
    assert_eq!(history.slices.front().unwrap().packet_no, 2);
    assert_eq!(history.slices.back().unwrap().packet_no, MAX_TCP_SLICES_PER_DIRECTION as u64 + 1);
}
