#[path = "support/http3.rs"]
mod support;
use Http3Sender::{Client, Server};
use packrat_tui::analysis::transactions::{MessageState, http3::*};
use support::*;

#[test]
fn bad_batch_identity_stream_types_and_ranges_are_rejected_before_retention() {
    let cases = [
        Http3Event {
            stream_id: 1,
            ..finished(Client, 0)
        },
        Http3Event {
            stream_id: u64::MAX,
            ..finished(Client, 0)
        },
        Http3Event {
            stream_id: 0,
            sender: Client,
            event: Http3EventKind::Extension {
                offset: u64::MAX,
                wire_length: 2,
                frame_type: 33,
            },
        },
        Http3Event {
            stream_id: 0,
            sender: Client,
            event: Http3EventKind::Data {
                offset: 0,
                wire_length: 2,
                data: vec![1],
            },
        },
    ];
    for event in cases {
        let mut tracker = Http3Tracker::default();
        assert!(
            tracker
                .ingest_authenticated(batch(vec![header_event(Client, 0, request()), event]), 1)
                .is_err()
        );
        assert_eq!(tracker.connection_ids().count(), 0);
        assert_eq!(tracker.rejected_batches, 1);
    }
    for bad in ["", "h2", "h3-29"] {
        let mut input = batch(vec![finished(Client, 0)]);
        input.alpn = bad.into();
        assert!(
            Http3Tracker::default()
                .ingest_authenticated(input, 1)
                .is_err()
        );
    }
}

#[test]
fn known_and_forbidden_frames_cannot_be_hidden_as_extensions() {
    for frame_type in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 13] {
        let event = Http3Event {
            stream_id: 0,
            sender: Client,
            event: Http3EventKind::Extension {
                offset: 0,
                wire_length: 2,
                frame_type,
            },
        };
        assert!(
            Http3Tracker::default()
                .ingest_authenticated(batch(vec![event]), 1)
                .is_err()
        );
    }
}

#[test]
fn malformed_headers_and_framing_never_become_complete_messages() {
    for fields in [
        headers(&[(":method", "GET"), (":scheme", "https"), (":path", "")]),
        headers(&[(":status", "200")]),
        headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            ("connection", "close"),
        ]),
        headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            ("content-length", "1"),
        ]),
        headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            ("X-Upper", "bad"),
        ]),
    ] {
        let mut tracker = Http3Tracker::default();
        tracker
            .ingest_authenticated(
                batch(vec![header_event(Client, 0, fields), finished(Client, 10)]),
                1,
            )
            .unwrap();
        assert_eq!(
            report(&tracker).transactions[0]
                .request
                .as_ref()
                .unwrap()
                .state,
            MessageState::Ambiguous
        );
    }
}

#[test]
fn head_content_length_is_metadata_but_body_bytes_are_a_violation() {
    for body in [false, true] {
        let mut tracker = Http3Tracker::default();
        let mut request = request();
        request[0].value = b"HEAD".to_vec();
        let mut events = vec![
            header_event(Client, 0, request),
            finished(Client, 10),
            header_event(
                Server,
                0,
                headers(&[(":status", "200"), ("content-length", "20")]),
            ),
        ];
        if body {
            events.push(data_event(Server, 10, b"x"));
        }
        events.push(finished(Server, if body { 13 } else { 10 }));
        tracker.ingest_authenticated(batch(events), 1).unwrap();
        assert_eq!(
            report(&tracker).transactions[0]
                .response
                .as_ref()
                .unwrap()
                .state,
            if body {
                MessageState::Ambiguous
            } else {
                MessageState::Complete
            }
        );
    }
}

#[test]
fn a_rejected_batch_marks_existing_connection_reports_incomplete() {
    let mut tracker = Http3Tracker::default();
    tracker
        .ingest_authenticated(
            batch(vec![
                header_event(Client, 0, request()),
                finished(Client, 10),
            ]),
            1,
        )
        .unwrap();
    let invalid = Http3Event {
        stream_id: 0,
        sender: Client,
        event: Http3EventKind::Data {
            offset: 10,
            wire_length: 1,
            data: vec![],
        },
    };
    assert!(
        tracker
            .ingest_authenticated(batch(vec![invalid]), 2)
            .is_err()
    );
    assert_eq!(
        report(&tracker).transactions[0]
            .request
            .as_ref()
            .unwrap()
            .state,
        MessageState::Incomplete
    );
}

#[test]
fn connections_headers_and_payload_retention_are_bounded_and_disclosed() {
    let mut tracker = Http3Tracker::default();
    for number in 0..64 {
        let mut input = batch(vec![finished(Client, 0)]);
        input.connection_id = format!("connection-{number}");
        tracker.ingest_authenticated(input, number).unwrap();
    }
    assert!(
        tracker
            .ingest_authenticated(batch(vec![finished(Client, 0)]), 65)
            .is_err()
    );
    assert_eq!(tracker.connection_ids().count(), 64);
    let mut input = batch(vec![header_event(Client, 0, request())]);
    if let Http3EventKind::Headers { headers, .. } = &mut input.events[0].event {
        headers.push(packrat_tui::analysis::transactions::HttpHeader {
            name: "large".into(),
            value: vec![b'x'; 65_536],
        });
    }
    assert!(
        Http3Tracker::default()
            .ingest_authenticated(input, 1)
            .is_err()
    );
    let mut tracker = Http3Tracker::default();
    tracker
        .ingest_authenticated(batch(vec![header_event(Client, 0, request())]), 1)
        .unwrap();
    let payload = vec![b'x'; 512 * 1024];
    let mut offset = 10;
    let mut rejected = false;
    for number in 2..=40 {
        let result =
            tracker.ingest_authenticated(batch(vec![data_event(Client, offset, &payload)]), number);
        if result.is_err() {
            rejected = true;
            break;
        }
        offset += payload.len() as u64 + 2;
    }
    assert!(rejected);
    assert!(
        report(&tracker)
            .limitations
            .iter()
            .any(|text| text.contains("incomplete"))
    );
}

#[test]
fn truncated_json_and_extreme_offsets_never_panic() {
    let encoded = serde_json::to_vec(&batch(vec![header_event(Client, 0, request())])).unwrap();
    for cut in 0..encoded.len() {
        assert!(serde_json::from_slice::<AuthenticatedHttp3Batch>(&encoded[..cut]).is_err());
    }
    for offset in [0, 1, 9, (1 << 62) - 1, u64::MAX] {
        for wire_length in [0, 1, 2, u64::MAX] {
            let mut tracker = Http3Tracker::default();
            let event = Http3Event {
                stream_id: 0,
                sender: Server,
                event: Http3EventKind::Extension {
                    offset,
                    wire_length,
                    frame_type: 33,
                },
            };
            let _ = tracker.ingest_authenticated(batch(vec![event]), 1);
            if let Some(report) = tracker.conversation("authenticated-connection") {
                assert_ne!(
                    report.transactions[0].response.as_ref().unwrap().state,
                    MessageState::Complete
                );
            }
        }
    }
}

#[test]
fn packet_lookup_is_bounded_and_conflicting_connection_attribution_is_rejected() {
    let mut tracker = Http3Tracker::default();
    for no in 1..=4097 {
        tracker
            .ingest_authenticated(batch(vec![finished(Client, 0)]), no)
            .unwrap();
    }
    assert_eq!(tracker.connection_for_packet(1), None);
    assert_eq!(
        tracker.connection_for_packet(4097),
        Some("authenticated-connection")
    );
    let before = tracker
        .connection_revision("authenticated-connection")
        .unwrap();
    let mut input = batch(vec![finished(Client, 0)]);
    input.connection_id = "other".into();
    assert!(tracker.ingest_authenticated(input, 4097).is_err());
    assert_eq!(
        tracker.connection_for_packet(4097),
        Some("authenticated-connection")
    );
    assert!(
        tracker
            .connection_revision("authenticated-connection")
            .unwrap()
            > before
    );
}
