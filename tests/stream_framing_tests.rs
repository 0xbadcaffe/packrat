#[path = "support/packets.rs"]
mod packets;

use packrat_tui::analysis::stream::{StreamAssembler, StreamKey};
use packrat_tui::net::packet::{CaptureMetadata, CaptureTimestamp, Packet, TimestampResolution};
use packrat_tui::net::parser::parse_ethernet;

#[test]
fn ethernet_padding_is_not_application_data() {
    let mut packet = packets::tcp(1, 100, 0x18, b"hello");
    packet.bytes.extend_from_slice(b"NOT IN IP PACKET");
    let mut assembler = StreamAssembler::default();
    assembler.ingest(&packet);
    let stream = assembler
        .get(&StreamKey::from_packet(&packet).unwrap().id())
        .unwrap();
    assert_eq!(stream.client_data, b"hello");
}

#[test]
fn fragmented_and_invalid_ip_lengths_are_not_reassembled_as_tcp() {
    for invalid in [0, 1, 2] {
        let mut packet = packets::tcp(1, 100, 0x18, b"not contiguous");
        match invalid {
            0 => packet.bytes[20..22].copy_from_slice(&0x2000u16.to_be_bytes()),
            1 => packet.bytes[20..22].copy_from_slice(&1u16.to_be_bytes()),
            _ => packet.bytes[16..18].copy_from_slice(&25u16.to_be_bytes()),
        }
        let mut assembler = StreamAssembler::default();
        assembler.ingest(&packet);
        assert!(assembler.is_empty());
    }
}

#[test]
fn truncated_capture_is_explicit_and_every_prefix_is_safe() {
    let mut packet = packets::tcp(1, 100, 0x18, b"hello world");
    for length in 0..packet.bytes.len() {
        let mut prefix = packet.clone();
        prefix.bytes.truncate(length);
        StreamAssembler::default().ingest(&prefix);
    }
    packet.bytes.truncate(packet.bytes.len() - 6);
    let mut assembler = StreamAssembler::default();
    assembler.ingest(&packet);
    let stream = assembler
        .get(&StreamKey::from_packet(&packet).unwrap().id())
        .unwrap();
    assert!(stream.truncated);
    assert_eq!(stream.client_data, b"hello");

    let captured_length = packet.bytes.len() as u32;
    packet.capture = Some(CaptureMetadata {
        timestamp: None, captured_length, wire_length: captured_length + 6, link_type: 1,
        section_id: 0, interface_id: 0, interface_name: None, comments: Vec::new(),
    });
    let mut assembler = StreamAssembler::default();
    assembler.ingest(&packet);
    let stream = assembler.get(&StreamKey::from_packet(&packet).unwrap().id()).unwrap();
    assert!(stream.truncated);
    assert_eq!(stream.client_data, b"hello");
    packet.capture.as_mut().unwrap().wire_length -= 1;
    let mut impossible = StreamAssembler::default();
    impossible.ingest(&packet);
    assert!(impossible.is_empty());
    let capture = packet.capture.as_mut().unwrap();
    capture.wire_length += 1;
    capture.captured_length -= 1;
    let mut inconsistent = StreamAssembler::default();
    inconsistent.ingest(&packet);
    assert!(inconsistent.is_empty());
}

#[test]
fn duplicate_syn_does_not_reset_the_reassembly_cursor() {
    let mut assembler = StreamAssembler::default();
    let syn = packets::tcp(1, 100, 0x02, &[]);
    let data = packets::tcp(2, 101, 0x18, b"hello");
    for packet in [&syn, &data, &syn, &data] {
        assembler.ingest(packet);
    }
    let stream = assembler
        .get(&StreamKey::from_packet(&data).unwrap().id())
        .unwrap();
    assert_eq!(stream.client_data, b"hello");
}

fn tagged(no: u64, outer: u16, inner: u16, payload: &[u8]) -> Packet {
    let packet = packets::tcp(no, 100, 0x18, payload);
    let mut bytes = packet.bytes[..12].to_vec();
    for value in [0x88a8u16, outer, 0x8100, inner] {
        bytes.extend(value.to_be_bytes());
    }
    bytes.extend(&packet.bytes[12..]);
    parse_ethernet(&bytes, no, no as f64)
}

#[test]
fn same_endpoints_on_different_qinq_scopes_never_share_bytes() {
    let left = tagged(1, 10, 20, b"tenant one");
    let right = tagged(2, 11, 20, b"tenant two");
    let mut assembler = StreamAssembler::default();
    for packet in [&left, &right] {
        assembler.ingest(packet);
    }
    assert_eq!(assembler.len(), 2);
    assert_eq!(
        assembler
            .get(&StreamKey::from_packet(&left).unwrap().id())
            .unwrap()
            .client_data,
        b"tenant one"
    );
    assert_eq!(
        assembler
            .get(&StreamKey::from_packet(&right).unwrap().id())
            .unwrap()
            .client_data,
        b"tenant two"
    );
}

#[test]
fn tcp_segments_are_isolated_by_ordered_wire_tag_types_not_priority() {
    let make = |frame, seq, tpids: [u16; 2], tci: u16, payload: &[u8]| {
        let original = packets::tcp(frame, seq, 0x18, payload);
        let mut raw = original.bytes;
        raw.splice(12..12, [tpids[0], tci, tpids[1], tci].into_iter().flat_map(u16::to_be_bytes));
        parse_ethernet(&raw, frame, frame as f64)
    };
    let first = make(1, 100, [0x88a8, 0x8100], 20, b"hello ");
    let different = make(2, 106, [0x8100, 0x88a8], 20, b"unrelated");
    let same = make(3, 106, [0x88a8, 0x8100], 0xb014, b"world");
    let mut assembler = StreamAssembler::default();
    for packet in [&first, &different, &same] {
        assembler.ingest(packet);
    }
    let key = |packet| StreamKey::from_packet(packet).unwrap().id();
    assert_ne!(key(&first), key(&different));
    assert_eq!(key(&first), key(&same));
    assert_eq!(assembler.len(), 2);
    assert_eq!(assembler.get(&key(&first)).unwrap().client_data, b"hello world");
    assert_eq!(assembler.get(&key(&different)).unwrap().client_data, b"unrelated");
}

#[test]
fn interfaces_and_sections_are_part_of_stream_identity() {
    let mut assembler = StreamAssembler::default();
    let mut ids = std::collections::HashSet::new();
    for (interface_id, section_id, name) in [
        (0, 0, None),
        (1, 0, None),
        (0, 1, None),
        (0, 0, Some("sensor0")),
        (0, 0, Some("sensor1")),
    ] {
        let mut packet = packets::tcp(1, 100, 0x18, b"isolated");
        packet.capture = Some(CaptureMetadata {
            timestamp: Some(CaptureTimestamp {
                ticks: 1,
                resolution: TimestampResolution::Decimal(0),
                offset_seconds: 0,
            }),
            captured_length: packet.bytes.len() as u32,
            wire_length: packet.bytes.len() as u32,
            link_type: 1,
            interface_id,
            section_id,
            interface_name: name.map(str::to_owned),
            comments: Vec::new(),
        });
        ids.insert(StreamKey::from_packet(&packet).unwrap().id());
        assembler.ingest(&packet);
    }
    assert_eq!(ids.len(), 5);
    assert_eq!(assembler.len(), 5);
}

#[test]
fn ipv6_atomic_fragments_are_allowed_but_partial_datagrams_are_not() {
    for fragment_flags in [0u16, 1, 8] {
        let packet = packets::tcp(1, 100, 0x18, b"ipv6");
        let mut bytes = vec![0; 62];
        bytes[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        bytes[14] = 0x60;
        bytes[18..20].copy_from_slice(&32u16.to_be_bytes());
        bytes[20] = 44;
        bytes[54] = 6;
        bytes[56..58].copy_from_slice(&fragment_flags.to_be_bytes());
        bytes.extend(&packet.bytes[34..]);
        let packet = parse_ethernet(&bytes, 1, 1.0);
        let mut assembler = StreamAssembler::default();
        assembler.ingest(&packet);
        assert_eq!(assembler.len(), usize::from(fragment_flags == 0));
    }
}
