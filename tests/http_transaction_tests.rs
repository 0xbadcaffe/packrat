#[path = "support/http.rs"]
mod support;

use packrat_tui::analysis::stream::{StreamAssembler, StreamKey};
use packrat_tui::analysis::transactions::{Direction, MessageState, reconstruct_http};
use support::{body, conversation, stream, tcp};

#[test]
fn pipelining_pairs_by_request_order_and_keeps_byte_spans() {
    let stream = stream(
        b"GET /one HTTP/1.1\r\nHost: example\r\n\r\nPOST /two HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\noneHTTP/1.1 201 Created\r\nContent-Length: 3, 3\r\n\r\ntwo",
    );
    let report = reconstruct_http(&stream);
    assert_eq!(report.transactions.len(), 2);
    for (transaction, target, code, expected) in [
        (&report.transactions[0], "/one", 200, b"one"),
        (&report.transactions[1], "/two", 201, b"two"),
    ] {
        assert_eq!(transaction.request.target.as_deref(), Some(target));
        let response = transaction.response.as_ref().unwrap();
        assert_eq!(response.status, Some(code));
        assert_eq!(response.state, MessageState::Complete);
        assert_eq!(body(&stream, response), expected);
    }
    assert_eq!(body(&stream, &report.transactions[1].request), b"abc");
}

#[test]
fn chunked_binary_data_extensions_and_trailers_are_separate_ranges() {
    let stream = stream(b"GET / HTTP/1.1\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;kind=binary\r\n\0\xffa\r\n2\r\nbc\r\n0\r\nDigest: opaque\r\n\r\n");
    let report = reconstruct_http(&stream);
    let response = report.transactions[0].response.as_ref().unwrap();
    assert_eq!(response.state, MessageState::Complete);
    assert_eq!(body(&stream, response), b"\0\xffabc");
    assert_eq!(response.body.len(), 2);
    assert_eq!(response.trailers[0].name, "Digest");
    assert_eq!(response.trailers[0].value, b"opaque");
    assert_eq!(response.span.end, stream.server_data.len());
}

#[test]
fn head_no_content_and_not_modified_do_not_consume_a_body() {
    let report = conversation(
        b"HEAD / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\nHTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 304 Not Modified\r\nContent-Length: 999\r\n\r\n");
    assert_eq!(report.transactions.len(), 3);
    for (transaction, status) in report.transactions.iter().zip([200, 204, 304]) {
        let response = transaction.response.as_ref().unwrap();
        assert_eq!(response.status, Some(status));
        assert_eq!(response.state, MessageState::Complete);
        assert_eq!(response.captured_body_bytes(), 0);
    }
}

#[test]
fn informational_responses_stay_with_the_final_exchange() {
    let report = conversation(b"POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\nx",
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let transaction = &report.transactions[0];
    assert_eq!(transaction.interim_responses.len(), 2);
    assert_eq!(transaction.response.as_ref().unwrap().status, Some(200));
}

#[test]
fn upgrades_and_connect_do_not_parse_tunnel_bytes_as_http() {
    for (request, response) in [
        (
            &b"CONNECT example:443 HTTP/1.1\r\n\r\n"[..],
            &b"HTTP/1.1 200 Connected\r\n\r\n"[..],
        ),
        (
            &b"GET / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"[..],
            &b"HTTP/1.1 101 Switching Protocols\r\n\r\n"[..],
        ),
    ] {
        let mut requests = request.to_vec();
        requests.extend_from_slice(b"GET /tunnel HTTP/1.1\r\n\r\n");
        let mut responses = response.to_vec();
        responses.extend_from_slice(b"\x16\x03\x03opaque");
        let report = conversation(&requests, &responses);
        assert_eq!(report.transactions.len(), 1);
        assert_eq!(
            report.transactions[0].response.as_ref().unwrap().span.end,
            response.len()
        );
        assert!(
            report
                .limitations
                .iter()
                .any(|text| text.contains("tunnel"))
        );
    }
}

#[test]
fn out_of_order_reconstruction_works_with_client_on_endpoint_b() {
    let mut assembler = StreamAssembler::default();
    let syn = tcp(1, 100, 0x02, &[], true);
    let key = StreamKey::from_packet(&syn).unwrap().id();
    assembler.ingest(&syn);
    assembler.ingest(&tcp(2, 500, 0x12, &[], false));
    let request = b"GET /reordered HTTP/1.1\r\nHost: example\r\n\r\n";
    assembler.ingest(&tcp(3, 111, 0x18, &request[10..], true));
    assembler.ingest(&tcp(4, 101, 0x18, &request[..10], true));
    assembler.ingest(&tcp(
        5,
        501,
        0x18,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        false,
    ));
    let report = reconstruct_http(assembler.get(&key).unwrap());
    assert_eq!(report.transactions.len(), 1);
    let transaction = &report.transactions[0];
    assert_eq!(transaction.request.span.direction, Direction::BtoA);
    assert_eq!(transaction.request.packet_numbers, [3, 4]);
    assert_eq!(transaction.response.as_ref().unwrap().packet_numbers, [5]);
}

#[test]
fn close_delimited_response_requires_its_own_clean_fin() {
    let mut assembler = StreamAssembler::default();
    let syn = tcp(1, 100, 0x02, &[], false);
    let key = StreamKey::from_packet(&syn).unwrap().id();
    assembler.ingest(&syn);
    assembler.ingest(&tcp(2, 500, 0x12, &[], true));
    let request = b"GET / HTTP/1.1\r\n\r\n";
    let response = b"HTTP/1.1 200 OK\r\n\r\nbody";
    assembler.ingest(&tcp(3, 101, 0x19, request, false));
    assembler.ingest(&tcp(4, 501, 0x18, response, true));
    let report = reconstruct_http(assembler.get(&key).unwrap());
    assert_eq!(
        report.transactions[0].response.as_ref().unwrap().state,
        MessageState::Incomplete
    );
    assembler.ingest(&tcp(5, 501 + response.len() as u32, 0x11, &[], true));
    let report = reconstruct_http(assembler.get(&key).unwrap());
    let message = report.transactions[0].response.as_ref().unwrap();
    assert_eq!(message.state, MessageState::Complete);
    assert_eq!(message.completion_packet, Some(5));
    assert_eq!(message.packet_numbers, [4, 5]);
}

#[test]
fn reset_or_missing_bytes_cannot_complete_an_eof_body() {
    for mode in 0..3 {
        let mut stream = stream(b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\nbody");
        stream.server_finished = true;
        match mode {
            0 => stream.reset = true,
            1 => stream.truncated = true,
            _ => stream.dropped_segments = 1,
        }
        let report = reconstruct_http(&stream);
        assert_eq!(
            report.transactions[0].response.as_ref().unwrap().state,
            MessageState::Incomplete
        );
        assert!(!report.limitations.is_empty());
    }
}
