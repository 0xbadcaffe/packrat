use packrat_tui::analysis::stream::{StreamAssembler, StreamKey, tcp_payload_offset};
use packrat_tui::net::packet::{CaptureMetadata, CaptureTimestamp, Packet, TimestampResolution};

fn tcp_packet(no: u64, sequence: u32, flags: u8, payload: &[u8]) -> Packet {
    let mut bytes = vec![0_u8; 14 + 20 + 20];
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    bytes[23] = 6;
    bytes[34..36].copy_from_slice(&40_000_u16.to_be_bytes());
    bytes[36..38].copy_from_slice(&443_u16.to_be_bytes());
    bytes[38..42].copy_from_slice(&sequence.to_be_bytes());
    bytes[46] = 0x50;
    bytes[47] = flags;
    bytes.extend_from_slice(payload);
    Packet { capture: None,
        no,
        timestamp: no as f64,
        src: "10.0.0.1".into(),
        dst: "10.0.0.2".into(),
        protocol: "TCP".into(),
        length: bytes.len() as u16,
        info: String::new(),
        src_port: Some(40_000),
        dst_port: Some(443),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes,
    }
}

fn stream(assembler: &StreamAssembler) -> &packrat_tui::analysis::stream::ReassembledStream {
    let key = StreamKey::from_packet(&tcp_packet(0, 0, 0, &[])).unwrap();
    assembler.get(&key.id()).unwrap()
}

fn ipv6_tcp_packet(no: u64, sequence: u32, payload: &[u8], hop_by_hop: bool) -> Packet {
    let extension_length = if hop_by_hop { 8 } else { 0 };
    let tcp_offset = 14 + 40 + extension_length;
    let mut bytes = vec![0_u8; tcp_offset + 20];
    bytes[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
    bytes[14] = 0x60;
    bytes[18..20].copy_from_slice(&((extension_length + 20 + payload.len()) as u16).to_be_bytes());
    bytes[20] = if hop_by_hop { 0 } else { 6 };
    if hop_by_hop {
        bytes[54] = 6;
        bytes[55] = 0;
    }
    bytes[tcp_offset..tcp_offset + 2].copy_from_slice(&40_000_u16.to_be_bytes());
    bytes[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&443_u16.to_be_bytes());
    bytes[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&sequence.to_be_bytes());
    bytes[tcp_offset + 12] = 0x50;
    bytes[tcp_offset + 13] = 0x18;
    bytes.extend_from_slice(payload);
    Packet { capture: None,
        no,
        timestamp: no as f64,
        src: "2001:db8::1".into(),
        dst: "2001:db8::2".into(),
        protocol: "TCP".into(),
        length: bytes.len() as u16,
        info: String::new(),
        src_port: Some(40_000),
        dst_port: Some(443),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes,
    }
}

#[test]
fn buffers_out_of_order_segments_until_the_gap_arrives() {
    let mut assembler = StreamAssembler::default();
    assembler.ingest(&tcp_packet(1, 1_000, 0x02, &[]));
    assembler.ingest(&tcp_packet(2, 1_006, 0x18, b"world"));
    assert!(stream(&assembler).client_data.is_empty());
    assembler.ingest(&tcp_packet(3, 1_001, 0x18, b"hello"));
    assert_eq!(stream(&assembler).client_data, b"helloworld");
}

#[test]
fn trims_retransmissions_and_partial_overlaps() {
    let mut assembler = StreamAssembler::default();
    assembler.ingest(&tcp_packet(1, 100, 0x02, &[]));
    assembler.ingest(&tcp_packet(2, 101, 0x18, b"hello"));
    assembler.ingest(&tcp_packet(3, 101, 0x18, b"hello"));
    assembler.ingest(&tcp_packet(4, 104, 0x18, b"loworld"));
    assert_eq!(stream(&assembler).client_data, b"helloworld");
}

#[test]
fn reassembles_across_tcp_sequence_wraparound() {
    let mut assembler = StreamAssembler::default();
    assembler.ingest(&tcp_packet(1, u32::MAX - 2, 0x02, &[]));
    assembler.ingest(&tcp_packet(2, u32::MAX - 1, 0x18, b"ab"));
    assembler.ingest(&tcp_packet(3, 2, 0x18, b"ef"));
    assembler.ingest(&tcp_packet(4, 0, 0x18, b"cd"));
    assert_eq!(stream(&assembler).client_data, b"abcdef");
}

#[test]
fn delays_out_of_order_fin_until_preceding_payload_is_complete() {
    let mut assembler = StreamAssembler::default();
    assembler.ingest(&tcp_packet(1, 10, 0x02, &[]));
    assembler.ingest(&tcp_packet(2, 13, 0x11, &[]));
    assert!(!stream(&assembler).closed);
    assembler.ingest(&tcp_packet(3, 11, 0x18, b"ab"));
    assert_eq!(stream(&assembler).client_data, b"ab");
    assert!(stream(&assembler).closed);
}

#[test]
fn reassembles_ipv6_tcp_with_and_without_extension_headers() {
    for hop_by_hop in [false, true] {
        let packet = ipv6_tcp_packet(1, 500, b"ipv6 payload", hop_by_hop);
        assert_eq!(&packet.bytes[tcp_payload_offset(&packet)..], b"ipv6 payload");
        let key = StreamKey::from_packet(&packet).unwrap();
        let mut assembler = StreamAssembler::default();
        assembler.ingest(&packet);
        assert_eq!(assembler.get(&key.id()).unwrap().client_data, b"ipv6 payload");
    }
}

#[test]
fn malformed_ip_and_tcp_headers_are_not_reassembled_as_payload() {
    let mut packet = tcp_packet(1, 100, 0x18, b"payload");
    packet.bytes[14] = 0x41;
    let key = StreamKey::from_packet(&packet).unwrap();
    let mut assembler = StreamAssembler::default();
    assembler.ingest(&packet);
    assert!(assembler.get(&key.id()).is_none());

    let mut packet = tcp_packet(2, 100, 0x18, b"payload");
    packet.bytes[46] = 0x10;
    assert_eq!(tcp_payload_offset(&packet), packet.bytes.len());
}

#[test]
fn non_finite_timestamps_do_not_crash_stream_sorting_or_eviction() {
    let mut assembler = StreamAssembler::default();
    for index in 0..520_u16 {
        let mut packet = tcp_packet(u64::from(index), 100, 0x18, b"x");
        packet.timestamp = if index % 2 == 0 { f64::NAN } else { f64::INFINITY };
        packet.src_port = Some(index.saturating_add(1));
        packet.bytes[34..36].copy_from_slice(&index.saturating_add(1).to_be_bytes());
        assembler.ingest(&packet);
    }
    assert_eq!(assembler.len(), 500);
    assert_eq!(assembler.all().len(), 500);
}

fn on_clock(mut packet: Packet, port: u16, seconds: u64, interface_id: u32) -> Packet {
    packet.src_port = Some(port);
    packet.bytes[34..36].copy_from_slice(&port.to_be_bytes());
    packet.timestamp = seconds as f64;
    let length = packet.bytes.len() as u32;
    packet.capture = Some(CaptureMetadata {
        timestamp: Some(CaptureTimestamp {
            ticks: seconds, resolution: TimestampResolution::Decimal(0), offset_seconds: 0,
        }),
        captured_length: length,
        wire_length: length,
        link_type: 1,
        section_id: 0,
        interface_id,
        interface_name: None,
        comments: Vec::new(),
    });
    packet
}

#[test]
fn stream_eviction_preserves_recent_reassembly_on_an_independent_clock() {
    let mut assembler = StreamAssembler::default();
    let oldest = on_clock(tcp_packet(1, 100, 0x02, b""), 30_000, 400, 1);
    let oldest_id = StreamKey::from_packet(&oldest).unwrap().id();
    assembler.ingest(&oldest);
    for i in 1..499_u16 {
        assembler.ingest(&on_clock(tcp_packet(u64::from(i) + 1, 100, 0x02, b""),
            30_000 + i, 400, 1));
    }
    let start = on_clock(tcp_packet(500, 100, 0x02, b""), 40_000, 10, 0);
    let recent_id = StreamKey::from_packet(&start).unwrap().id();
    assembler.ingest(&start);
    assembler.ingest(&on_clock(tcp_packet(501, 101, 0x18, b"hello"), 40_000, 11, 0));
    assembler.ingest(&on_clock(tcp_packet(502, 100, 0x02, b""), 50_000, 400, 1));
    assert_eq!(assembler.evicted_streams(), 1);
    assert!(assembler.get(&oldest_id).is_none());

    assembler.ingest(&on_clock(tcp_packet(503, 106, 0x18, b" world"), 40_000, 12, 0));
    let stream = assembler.get(&recent_id).unwrap();
    assert_eq!(stream.client_data, b"hello world");
    assert_eq!(stream.packet_numbers(true, 0, 11), [501, 503]);
    assert_eq!(assembler.evicted_streams(), 1);
}

#[test]
fn late_stream_packet_refreshes_eviction_order_without_rewriting_event_time() {
    let mut assembler = StreamAssembler::default();
    let original = on_clock(tcp_packet(1, 100, 0x02, b""), 40_000, 20, 0);
    let original_id = StreamKey::from_packet(&original).unwrap().id();
    assembler.ingest(&original);
    for i in 1..500_u16 {
        assembler.ingest(&on_clock(tcp_packet(u64::from(i) + 1, 100, 0x02, b""),
            30_000 + i, 30, 0));
    }
    assembler.ingest(&on_clock(tcp_packet(501, 101, 0x18, b"data"), 40_000, 19, 0));
    assembler.ingest(&on_clock(tcp_packet(502, 100, 0x02, b""), 50_000, 30, 0));
    let stream = assembler.get(&original_id).expect("recent observation should have kept the stream");
    assert_eq!(stream.client_data, b"data");
    assert_eq!(stream.last_seen, 20.0);
    assert_eq!(assembler.len(), 500);
}

#[test]
fn offline_alert_summary_keeps_stream_evictions_separate_from_skipped_packets() {
    use packrat_tui::export::pcapng::PcapNgWriter;
    use std::process::Command;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("stream-capacity.pcapng");
    let mut writer = PcapNgWriter::create(&path).unwrap();
    for i in 0..501_u16 {
        let frame = u64::from(i) + 1;
        let mut packet = tcp_packet(frame, 100, 0x02, b"");
        packet.bytes[26..34].copy_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        let packet = on_clock(packet, 30_000 + i, frame, 0);
        writer.write_packet(&packet).unwrap();
    }
    writer.flush().unwrap();
    for options in [&[][..], &["--alerts-only"][..]] {
        let output = Command::new(env!("CARGO_BIN_EXE_packrat-analyze")).args(options).arg(&path).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let text = String::from_utf8(output.stdout).unwrap();
        let summary: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        assert_eq!(summary["type"], "summary");
        assert_eq!(summary["analyzed"], 501);
        assert_eq!(summary["skipped"], 0);
        assert_eq!(summary["retained_streams"], 500);
        assert_eq!(summary["evicted_streams"], 1);
    }
}
