#[path = "support/packets.rs"]
mod packets;

use packrat_tui::analysis::stream::{StreamAssembler, StreamKey};

#[test]
fn reordered_bytes_keep_the_packet_that_actually_contributed_them() {
    let mut assembler = StreamAssembler::default();
    let syn = packets::tcp(1, 100, 0x02, &[]);
    let key = StreamKey::from_packet(&syn).unwrap().id();
    assembler.ingest(&syn);
    assembler.ingest(&packets::tcp(2, 106, 0x18, b"world"));
    assembler.ingest(&packets::tcp(3, 101, 0x18, b"hello"));
    assembler.ingest(&packets::tcp(4, 101, 0x18, b"hello"));
    let stream = assembler.get(&key).unwrap();
    assert_eq!(stream.packet_numbers(true, 0, 5), [3]);
    assert_eq!(stream.packet_numbers(true, 5, 10), [2]);
    assert_eq!(stream.packet_numbers(true, 0, 10), [2, 3]);
    assert!(!stream.has_gaps());
}

#[test]
fn fin_marks_only_its_direction_and_reset_is_not_a_clean_eof() {
    let mut assembler = StreamAssembler::default();
    let syn = packets::tcp(1, 100, 0x02, &[]);
    let key = StreamKey::from_packet(&syn).unwrap().id();
    assembler.ingest(&syn);
    assembler.ingest(&packets::tcp(2, 101, 0x11, &[]));
    let stream = assembler.get(&key).unwrap();
    assert!(stream.client_finished);
    assert!(!stream.server_finished);
    assembler.ingest(&packets::tcp(3, 102, 0x04, &[]));
    assembler.ingest(&packets::tcp(4, 102, 0x18, b"after reset"));
    assert!(assembler.get(&key).unwrap().reset);
    assert!(assembler.get(&key).unwrap().client_data.is_empty());
}

#[test]
fn reordered_fin_keeps_its_packet_identity_and_rejects_bytes_after_close() {
    let mut assembler = StreamAssembler::default();
    let syn = packets::tcp(1, 100, 0x02, &[]);
    let key = StreamKey::from_packet(&syn).unwrap().id();
    assembler.ingest(&syn);
    assembler.ingest(&packets::tcp(2, 106, 0x11, &[]));
    assert!(!assembler.get(&key).unwrap().client_finished);
    assembler.ingest(&packets::tcp(3, 101, 0x18, b"hello"));
    assembler.ingest(&packets::tcp(4, 107, 0x18, b"not in stream"));
    let stream = assembler.get(&key).unwrap();
    assert!(stream.client_finished);
    assert_eq!(stream.client_fin_packet, Some(2));
    assert_eq!(stream.client_data, b"hello");
}

#[test]
fn pending_and_byte_retention_limits_are_visible_in_stream_quality() {
    let syn = packets::tcp(1, 100, 0x02, &[]);
    let key = StreamKey::from_packet(&syn).unwrap().id();
    let mut pending = StreamAssembler::default();
    pending.ingest(&syn);
    for index in 0..1025 {
        pending.ingest(&packets::tcp(2 + index as u64, 10_000 + index, 0x18, b"x"));
    }
    let stream = pending.get(&key).unwrap();
    assert_eq!(stream.pending_segments(), 1024);
    assert_eq!(stream.dropped_segments, 1);
    assert!(stream.has_gaps());

    let mut bounded = StreamAssembler::default();
    bounded.ingest(&syn);
    for index in 0..17 {
        bounded.ingest(&packets::tcp(
            2 + index as u64,
            101 + index * 60_000,
            0x18,
            &vec![b'x'; 60_000],
        ));
    }
    let stream = bounded.get(&key).unwrap();
    assert_eq!(stream.client_data.len(), 1_000_000);
    assert!(stream.truncated);
}

#[test]
fn segment_metadata_is_bounded_without_claiming_complete_provenance() {
    let mut assembler = StreamAssembler::default();
    let syn = packets::tcp(1, 100, 0x02, &[]);
    let key = StreamKey::from_packet(&syn).unwrap().id();
    assembler.ingest(&syn);
    for index in 0..8300 {
        assembler.ingest(&packets::tcp(index as u64 + 2, 101 + index, 0x18, b"x"));
    }
    let stream = assembler.get(&key).unwrap();
    assert_eq!(stream.segments.len(), 8192);
    assert!(stream.provenance_truncated);
    assert_eq!(stream.client_data.len(), 8300);
}

#[test]
fn a_new_syn_epoch_does_not_mix_connections_into_one_byte_sequence() {
    let mut assembler = StreamAssembler::default();
    let syn = packets::tcp(1, 100, 0x02, &[]);
    let key = StreamKey::from_packet(&syn).unwrap().id();
    assembler.ingest(&syn);
    assembler.ingest(&packets::tcp(2, 101, 0x18, b"first"));
    assembler.ingest(&packets::tcp(3, 500, 0x02, &[]));
    assembler.ingest(&packets::tcp(4, 501, 0x18, b"second"));
    let stream = assembler.get(&key).unwrap();
    assert!(stream.epoch_ambiguous);
    assert_eq!(stream.client_data, b"first");
}
