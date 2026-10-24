#[path = "support/http2.rs"]
mod support;

use packrat_tui::analysis::transactions::{MessageState, reconstruct_http2};
use support::*;

#[test]
fn interleaved_streams_pair_by_id_not_response_order() {
    let mut client = frame(1, 5, 1, &request(b"/one"));
    client.extend(frame(1, 5, 3, &request(b"/two")));
    let mut server = frame(1, 4, 3, &[0x88]);
    server.extend(frame(0, 1, 3, b"two"));
    server.extend(frame(1, 4, 1, &[0x88]));
    server.extend(frame(0, 1, 1, b"one"));
    let stream = stream(&client, &server);
    let report = reconstruct_http2(&stream);
    assert!(report.limitations.is_empty(), "{:?}", report.limitations);
    assert_eq!(report.transactions.len(), 2);
    for (transaction, path, expected) in [
        (&report.transactions[0], &b"/one"[..], &b"one"[..]),
        (&report.transactions[1], &b"/two"[..], &b"two"[..]),
    ] {
        assert_eq!(
            transaction.request.as_ref().unwrap().header(":path"),
            Some(path)
        );
        let response = transaction.response.as_ref().unwrap();
        assert_eq!(response.state, MessageState::Complete);
        let bytes: Vec<_> = response
            .body
            .iter()
            .flat_map(|span| {
                span.direction.bytes(&stream)[span.start..span.end]
                    .iter()
                    .copied()
            })
            .collect();
        assert_eq!(bytes, expected);
    }
}

#[test]
fn continuation_and_directional_dynamic_tables_preserve_headers() {
    let mut encoder = loona_hpack::Encoder::new();
    let first = encoder.encode([
        (b":method".as_slice(), b"GET".as_slice()),
        (b":scheme", b"https"),
        (b":path", b"/"),
        (b"x-session", b"opaque"),
    ]);
    let second = encoder.encode([
        (b":method".as_slice(), b"GET".as_slice()),
        (b":scheme", b"https"),
        (b":path", b"/"),
        (b"x-session", b"opaque"),
    ]);
    assert!(second.len() < first.len());
    let split = first.len() / 2;
    let mut client = frame(1, 1, 1, &first[..split]);
    client.extend(frame(9, 4, 1, &first[split..]));
    client.extend(frame(1, 5, 3, &second));
    let report = reconstruct_http2(&stream(&client, &frame(1, 5, 1, &[0x88])));
    assert!(report.limitations.is_empty(), "{:?}", report.limitations);
    for transaction in &report.transactions {
        assert_eq!(
            transaction.request.as_ref().unwrap().header("x-session"),
            Some(b"opaque".as_slice())
        );
    }
}

#[test]
fn huffman_headers_decode_using_the_library() {
    let block = [
        0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90,
        0xf4, 0xff,
    ];
    let report = reconstruct_http2(&stream(&frame(1, 5, 1, &block), &[]));
    assert!(report.limitations.is_empty());
    assert_eq!(
        report.transactions[0]
            .request
            .as_ref()
            .unwrap()
            .header(":authority"),
        Some(b"www.example.com".as_slice())
    );
}

#[test]
fn data_padding_trailers_and_informational_responses_are_distinct() {
    let mut server = frame(1, 4, 1, &headers(&[(b":status", b"103")]));
    server.extend(frame(1, 4, 1, &[0x88]));
    server.extend(frame(0, 8, 1, b"\x02body\0\0"));
    server.extend(frame(1, 5, 1, &headers(&[(b"digest", b"opaque")])));
    let report = reconstruct_http2(&stream(&frame(1, 5, 1, &request(b"/")), &server));
    let transaction = &report.transactions[0];
    assert_eq!(transaction.interim_responses.len(), 1);
    let response = transaction.response.as_ref().unwrap();
    assert_eq!(response.body_bytes(), 4);
    assert_eq!(response.trailers[0].name, "digest");
    assert_eq!(response.state, MessageState::Complete);
}

#[test]
fn reset_goaway_and_capture_gaps_are_not_successful_completion() {
    let mut server = frame(1, 4, 1, &[0x88]);
    server.extend(frame(3, 0, 1, &8u32.to_be_bytes()));
    let mut goaway = 1u32.to_be_bytes().to_vec();
    goaway.extend(0u32.to_be_bytes());
    server.extend(frame(7, 0, 0, &goaway));
    let report = reconstruct_http2(&stream(&frame(1, 5, 1, &request(b"/")), &server));
    assert_eq!(report.transactions[0].reset_code, Some(8));
    assert_eq!(report.goaway_stream, Some(1));
    assert_eq!(
        report.transactions[0].response.as_ref().unwrap().state,
        MessageState::Incomplete
    );
    let mut capture = stream(&frame(1, 5, 1, &request(b"/")), &frame(1, 5, 1, &[0x88]));
    capture.truncated = true;
    let report = reconstruct_http2(&capture);
    assert_eq!(
        report.transactions[0].response.as_ref().unwrap().state,
        MessageState::Incomplete
    );
}

#[test]
fn pushed_request_has_its_own_stream_and_parent() {
    let mut promise = 2u32.to_be_bytes().to_vec();
    promise.extend(request(b"/pushed"));
    let mut server = frame(5, 4, 1, &promise);
    server.extend(frame(1, 5, 2, &[0x88]));
    server.extend(frame(1, 5, 1, &[0x88]));
    let report = reconstruct_http2(&stream(&frame(1, 5, 1, &request(b"/")), &server));
    assert!(report.limitations.is_empty(), "{:?}", report.limitations);
    let pushed = &report.transactions[1];
    assert_eq!(pushed.stream_id, 2);
    assert_eq!(pushed.promised_by, Some(1));
    assert_eq!(
        pushed.request.as_ref().unwrap().state,
        MessageState::Complete
    );
}

#[test]
fn head_response_content_length_describes_metadata_not_data() {
    let request = headers(&[
        (b":method", b"HEAD"),
        (b":scheme", b"https"),
        (b":path", b"/"),
    ]);
    let response = headers(&[(b":status", b"200"), (b"content-length", b"999")]);
    let report = reconstruct_http2(&stream(
        &frame(1, 5, 1, &request),
        &frame(1, 5, 1, &response),
    ));
    assert_eq!(
        report.transactions[0].response.as_ref().unwrap().state,
        MessageState::Complete
    );
}
