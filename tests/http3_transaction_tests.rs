#[path = "support/http3.rs"]
mod support;
use Http3Sender::{Client, Server};
use packrat_tui::analysis::transactions::{MessageState, http3::*};
use support::*;

#[test]
fn correlates_authenticated_request_response_and_body_with_packet_evidence() {
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
    tracker
        .ingest_authenticated(
            batch(vec![
                header_event(
                    Server,
                    0,
                    headers(&[(":status", "200"), ("content-length", "2")]),
                ),
                data_event(Server, 10, b"ok"),
                finished(Server, 14),
            ]),
            2,
        )
        .unwrap();
    let report = report(&tracker);
    let exchange = &report.transactions[0];
    assert_eq!(
        exchange.request.as_ref().unwrap().state,
        MessageState::Complete
    );
    let response = exchange.response.as_ref().unwrap();
    assert_eq!(response.state, MessageState::Complete);
    assert_eq!(response.body[0].data, b"ok");
    assert_eq!(response.body[0].frame_offset, 10);
    assert_eq!(response.packet_numbers, [2]);
    assert_eq!(
        tracker.connection_for_packet(1),
        Some("authenticated-connection")
    );
}

#[test]
fn reorders_frames_and_fin_without_hiding_gaps() {
    let mut tracker = Http3Tracker::default();
    tracker
        .ingest_authenticated(
            batch(vec![data_event(Client, 10, b"data"), finished(Client, 16)]),
            2,
        )
        .unwrap();
    assert_eq!(
        report(&tracker).transactions[0]
            .request
            .as_ref()
            .unwrap()
            .state,
        MessageState::Incomplete
    );
    tracker
        .ingest_authenticated(batch(vec![header_event(Client, 0, request())]), 1)
        .unwrap();
    let report = report(&tracker);
    let request = report.transactions[0].request.as_ref().unwrap();
    assert_eq!(request.state, MessageState::Complete);
    assert_eq!(request.packet_numbers, [1, 2]);
}

#[test]
fn duplicate_frames_preserve_first_bytes_and_conflicts_are_ambiguous() {
    let mut tracker = Http3Tracker::default();
    let event = header_event(Client, 0, request());
    tracker
        .ingest_authenticated(batch(vec![event.clone(), finished(Client, 10)]), 1)
        .unwrap();
    tracker.ingest_authenticated(batch(vec![event]), 2).unwrap();
    assert_eq!(
        report(&tracker).transactions[0]
            .request
            .as_ref()
            .unwrap()
            .packet_numbers,
        [1, 2]
    );
    let mut changed = request();
    changed[2].value = b"/different".to_vec();
    tracker
        .ingest_authenticated(batch(vec![header_event(Client, 0, changed)]), 3)
        .unwrap();
    let report = report(&tracker);
    let request = report.transactions[0].request.as_ref().unwrap();
    assert_eq!(request.state, MessageState::Ambiguous);
    assert_eq!(request.header(":path"), Some(b"/inspect".as_slice()));
}

#[test]
fn overlapping_ranges_and_conflicting_final_sizes_cannot_be_complete() {
    for event in [data_event(Client, 5, b"bad"), finished(Client, 11)] {
        let mut tracker = Http3Tracker::default();
        tracker
            .ingest_authenticated(
                batch(vec![
                    header_event(Client, 0, request()),
                    finished(Client, 10),
                    event,
                ]),
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
fn interim_response_trailers_and_multiplexed_streams_remain_separate() {
    let mut tracker = Http3Tracker::default();
    let mut events = vec![
        header_event(Server, 0, headers(&[(":status", "103")])),
        header_event(Server, 10, headers(&[(":status", "200")])),
        data_event(Server, 20, b"ok"),
        header_event(Server, 24, headers(&[("checksum", "abc")])),
        finished(Server, 34),
    ];
    let mut other = header_event(Client, 0, request());
    other.stream_id = 4;
    events.push(other);
    tracker.ingest_authenticated(batch(events), 4).unwrap();
    let report = report(&tracker);
    assert_eq!(report.transactions.len(), 2);
    let exchange = &report.transactions[0];
    assert_eq!(exchange.interim_responses.len(), 1);
    assert_eq!(
        exchange.response.as_ref().unwrap().trailers[0].name,
        "checksum"
    );
    assert_eq!(
        exchange.response.as_ref().unwrap().state,
        MessageState::Complete
    );
    assert!(report.transactions[1].response.is_none());
}

#[test]
fn reset_retains_body_but_never_claims_a_complete_message() {
    let mut tracker = Http3Tracker::default();
    tracker
        .ingest_authenticated(
            batch(vec![
                header_event(Client, 0, request()),
                data_event(Client, 10, b"part"),
                Http3Event {
                    stream_id: 0,
                    sender: Client,
                    event: Http3EventKind::Reset {
                        final_size: 16,
                        error_code: 0x10c,
                    },
                },
            ]),
            1,
        )
        .unwrap();
    let report = report(&tracker);
    let message = report.transactions[0].request.as_ref().unwrap();
    assert_eq!(message.state, MessageState::Incomplete);
    assert_eq!(message.body_bytes(), 4);
    assert_eq!(message.reset_code, Some(0x10c));
}
