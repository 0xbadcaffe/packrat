#[path = "support/http.rs"]
mod support;

use packrat_tui::analysis::transactions::{MessageState, reconstruct_http};
use support::{conversation, stream};

#[test]
fn ambiguous_request_framing_does_not_resynchronize_into_a_fake_request() {
    for header in [
        "Content-Length: 1\r\nContent-Length: 2",
        "Transfer-Encoding: chunked\r\nContent-Length: 1",
        "Content-Length: -1",
        "Content-Length: +1",
        "Content-Length:",
        "Content-Length: 184467440737095516160000000",
    ] {
        let request = format!("POST / HTTP/1.1\r\n{header}\r\n\r\nxGET /fake HTTP/1.1\r\n\r\n");
        let report = conversation(request.as_bytes(), b"");
        assert_eq!(report.transactions.len(), 1, "{header}");
        assert_eq!(
            report.transactions[0].request.state,
            MessageState::Ambiguous,
            "{header}"
        );
    }
}

#[test]
fn invalid_chunks_trailers_and_line_endings_are_not_complete() {
    for body in [
        &b"\r\n"[..],
        &b";extension\r\n"[..],
        &b"z\r\n"[..],
        &b"1\r\nx!!"[..],
        &b"0\r\nContent-Length: 0\r\n\r\n"[..],
        &b"0\r\nX-Trailer: value\n\n"[..],
    ] {
        let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        response.extend_from_slice(body);
        let report = conversation(b"GET / HTTP/1.1\r\n\r\n", &response);
        assert_eq!(
            report.transactions[0].response.as_ref().unwrap().state,
            MessageState::Ambiguous,
            "{body:?}"
        );
    }
    let report = conversation(b"GET / HTTP/1.1\nHost: example\n\n", b"");
    assert_eq!(
        report.transactions[0].request.state,
        MessageState::Ambiguous
    );
}

#[test]
fn unsupported_transfer_codings_are_explicit() {
    for encoding in ["gzip", "gzip, chunked", "chunked, chunked", "chunked,"] {
        let request = format!("POST / HTTP/1.1\r\nTransfer-Encoding: {encoding}\r\n\r\n0\r\n\r\n");
        let report = conversation(request.as_bytes(), b"");
        assert_eq!(
            report.transactions[0].request.state,
            MessageState::Unsupported
        );
    }
}

#[test]
fn invalid_status_codes_and_hidden_chunk_controls_are_ambiguous() {
    for status in ["000", "099", "600", "999"] {
        let response = format!("HTTP/1.1 {status} Invalid\r\nContent-Length: 0\r\n\r\n");
        let report = conversation(b"GET / HTTP/1.1\r\n\r\n", response.as_bytes());
        assert_eq!(
            report.transactions[0].response.as_ref().unwrap().state,
            MessageState::Ambiguous
        );
    }
    for extension in [
        &b"kind=bad\nhidden"[..],
        &b"kind=\0bad"[..],
        &b"kind=\x7fbad"[..],
    ] {
        let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;".to_vec();
        response.extend_from_slice(extension);
        response.extend_from_slice(b"\r\nx\r\n0\r\n\r\n");
        let report = conversation(b"GET / HTTP/1.1\r\n\r\n", &response);
        assert_eq!(
            report.transactions[0].response.as_ref().unwrap().state,
            MessageState::Ambiguous
        );
    }
}

#[test]
fn incomplete_response_prevents_later_response_mispairing() {
    let report = conversation(
        b"GET /one HTTP/1.1\r\n\r\nGET /two HTTP/1.1\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort",
    );
    assert_eq!(report.transactions.len(), 2);
    assert_eq!(
        report.transactions[0].response.as_ref().unwrap().state,
        MessageState::Incomplete
    );
    assert!(report.transactions[1].response.is_none());
}

#[test]
fn every_capture_prefix_has_safe_in_range_spans() {
    let request = b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc";
    let response =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX: y\r\n\r\n";
    for request_end in 0..=request.len() {
        for response_end in 0..=response.len() {
            let stream = stream(&request[..request_end], &response[..response_end]);
            let report = reconstruct_http(&stream);
            for transaction in report.transactions {
                for message in std::iter::once(transaction.request)
                    .chain(transaction.interim_responses)
                    .chain(transaction.response)
                {
                    assert!(message.span.start <= message.header_end);
                    assert!(message.header_end <= message.span.end);
                    assert!(message.span.end <= message.span.direction.bytes(&stream).len());
                    for span in message.body {
                        assert!(span.start <= span.end);
                        assert!(span.end <= span.direction.bytes(&stream).len());
                    }
                }
            }
        }
    }
}

#[test]
fn retention_limits_remain_bounded_and_visible() {
    let requests = b"GET / HTTP/1.1\r\n\r\n".repeat(129);
    let report = conversation(&requests, b"");
    assert_eq!(report.transactions.len(), 128);
    assert!(report.limitations.iter().any(|text| text.contains("count")));
    let long = format!("GET / HTTP/1.1\r\nX: {}", "x".repeat(70_000));
    let report = conversation(long.as_bytes(), b"");
    assert_eq!(
        report.transactions[0].request.state,
        MessageState::Unsupported
    );
    let mut chunks = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    chunks.extend(b"1\r\nx\r\n".repeat(8193));
    chunks.extend_from_slice(b"0\r\n\r\n");
    let report = conversation(b"GET / HTTP/1.1\r\n\r\n", &chunks);
    assert_eq!(
        report.transactions[0].response.as_ref().unwrap().state,
        MessageState::Unsupported
    );
}

#[test]
fn unsupported_protocols_and_ambiguous_direction_are_not_guessed() {
    for (request, response) in [
        (&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..], &b""[..]),
        (&b"\x16\x03\x03encrypted"[..], &b""[..]),
        (
            &b"GET / HTTP/1.1\r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\n\r\n"[..],
        ),
    ] {
        let report = conversation(request, response);
        assert!(report.transactions.is_empty());
        assert!(!report.limitations.is_empty());
    }
}
