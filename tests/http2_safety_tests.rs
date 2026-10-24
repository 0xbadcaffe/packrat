#[path = "support/http2.rs"]
mod support;
use packrat_tui::analysis::transactions::{MessageState, reconstruct_http2};
use support::*;

#[test]
fn malformed_frames_and_interrupted_continuations_stop_the_direction() {
    for bytes in [
        frame(0, 1, 0, b"bad"),
        frame(1, 5, 2, &request(b"/")),
        frame(3, 0, 0, &[0; 4]),
        frame(6, 0, 0, &[0; 7]),
        frame(8, 0, 0, &[0; 4]),
        frame(0, 8, 1, b"\xffbad"),
    ] {
        let report = reconstruct_http2(&stream(&bytes, &[]));
        assert!(!report.limitations.is_empty());
    }
    let mut bytes = frame(1, 1, 1, &[0x82]);
    bytes.extend(frame(6, 0, 0, &[0; 8]));
    assert!(
        reconstruct_http2(&stream(&bytes, &[]))
            .limitations
            .iter()
            .any(|value| value.contains("interrupted"))
    );
}

#[test]
fn invalid_pseudo_headers_and_connection_fields_remain_ambiguous() {
    for fields in [
        vec![(b":method".as_slice(), b"GET".as_slice())],
        vec![
            (b":method".as_slice(), b"GET".as_slice()),
            (b":scheme", b"https"),
            (b":path", b"/"),
            (b"connection", b"close"),
        ],
        vec![
            (b"x", b"y"),
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":path", b"/"),
        ],
    ] {
        let report = reconstruct_http2(&stream(&frame(1, 5, 1, &headers(&fields)), &[]));
        assert_eq!(
            report.transactions[0].request.as_ref().unwrap().state,
            MessageState::Ambiguous
        );
    }
}

#[test]
fn every_cutoff_and_many_arbitrary_hpack_blocks_are_panic_free() {
    let request_frame = frame(1, 5, 1, &request(b"/safe"));
    let response_frame = frame(1, 5, 1, &[0x88]);
    let full = stream(&request_frame, &response_frame);
    for end in 0..=full.client_data.len() {
        let mut cut = full.clone();
        cut.client_data.truncate(end);
        reconstruct_http2(&cut);
    }
    let mut seed = 1u32;
    for len in 1..=64 {
        for _ in 0..32 {
            let mut block = Vec::new();
            for _ in 0..len {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                block.push(seed as u8);
            }
            reconstruct_http2(&stream(&frame(1, 5, 1, &block), &[]));
        }
    }
    for block in [
        &b"\x3f\xff"[..],
        &b"\xff"[..],
        &b"\x40\xff"[..],
        &b"\x80"[..],
    ] {
        assert!(
            !reconstruct_http2(&stream(&frame(1, 5, 1, block), &[]))
                .limitations
                .is_empty()
        );
    }
}

#[test]
fn header_and_transaction_resource_limits_are_reported() {
    let report = reconstruct_http2(&stream(&frame(1, 5, 1, &vec![0x82; 129]), &[]));
    assert!(
        report
            .limitations
            .iter()
            .any(|value| value.contains("limit"))
    );
    let mut frames = Vec::new();
    for id in 0..129 {
        frames.extend(frame(1, 5, id * 2 + 1, &[0x82, 0x87, 0x84]));
    }
    let report = reconstruct_http2(&stream(&frames, &[]));
    assert_eq!(report.transactions.len(), 128);
    assert!(
        report
            .limitations
            .iter()
            .any(|value| value.contains("limit"))
    );
}

#[test]
fn unknown_compression_context_and_missing_preface_are_not_guessed() {
    let mut capture = stream(&frame(1, 5, 1, &[0xbe]), &[]);
    assert!(!reconstruct_http2(&capture).limitations.is_empty());
    capture.client_data.drain(..PREFACE.len());
    assert!(reconstruct_http2(&capture).transactions.is_empty());
}
