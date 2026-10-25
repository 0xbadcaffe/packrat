#[path = "support/http3_control.rs"]
mod control;
#[path = "support/http3_push.rs"]
mod push_fixture;
#[path = "support/http3.rs"]
mod support;
use Http3Sender::{Client, Server};
use packrat_tui::analysis::transactions::{MessageState, http3::*};
use support::*;

#[test]
fn push_ids_above_captured_credit_and_cancellations_above_credit_are_flagged() {
    let mut tracker = Http3Tracker::default();
    let mut events = push_fixture::credit(0);
    events.push(push_fixture::promise(0, 0, 1));
    events.extend(push_fixture::response(7, 1, b"ok"));
    events.push(control::event(
        Client,
        Http3EventKind::CancelPush {
            offset: 6,
            wire_length: 3,
            push_id: 1,
        },
    ));
    tracker.ingest_authenticated(batch(events), 1).unwrap();
    let report = report(&tracker);
    assert_eq!(report.pushes[0].state, MessageState::Ambiguous);
    assert_eq!(report.control_streams[0].state, MessageState::Ambiguous);
}

#[test]
fn a_late_larger_grant_can_resolve_a_provisional_push_credit_mismatch() {
    let mut tracker = Http3Tracker::default();
    let mut events = push_fixture::credit(0);
    events.push(push_fixture::promise(0, 0, 1));
    events.extend(push_fixture::response(7, 1, b"ok"));
    tracker.ingest_authenticated(batch(events), 1).unwrap();
    assert_eq!(report(&tracker).pushes[0].state, MessageState::Ambiguous);
    tracker
        .ingest_authenticated(batch(vec![control::credit(6, 1)]), 2)
        .unwrap();
    assert_eq!(report(&tracker).pushes[0].state, MessageState::Complete);
}

#[test]
fn wrong_push_senders_and_promises_on_unidirectional_streams_are_rejected() {
    for event in [
        Http3Event {
            stream_id: 2,
            sender: Client,
            event: Http3EventKind::PushStart {
                wire_length: 2,
                push_id: 0,
            },
        },
        Http3Event {
            sender: Client,
            ..push_fixture::promise(0, 0, 0)
        },
        push_fixture::promise(7, 0, 0),
        Http3Event {
            stream_id: 7,
            sender: Server,
            event: Http3EventKind::PushStart {
                wire_length: 2,
                push_id: u64::MAX,
            },
        },
    ] {
        let mut tracker = Http3Tracker::default();
        assert!(tracker.ingest_authenticated(batch(vec![event]), 1).is_err());
        assert_eq!(tracker.connection_ids().count(), 0);
    }
}

#[test]
fn promises_reject_missing_authority_and_request_content() {
    for missing_authority in [false, true] {
        let mut promise = push_fixture::promise(0, 0, 0);
        if let Http3EventKind::PushPromise { headers, .. } = &mut promise.event {
            if missing_authority {
                headers.retain(|header| header.name != ":authority");
            } else {
                headers.extend(support::headers(&[("content-length", "1")]));
            }
        }
        let mut tracker = Http3Tracker::default();
        tracker
            .ingest_authenticated(batch(vec![promise]), 1)
            .unwrap();
        assert_eq!(report(&tracker).pushes[0].state, MessageState::Ambiguous);
    }
}

#[test]
fn a_capture_gap_in_the_promising_direction_cannot_be_declared_complete() {
    let mut events = push_fixture::credit(0);
    events.push(push_fixture::promise(0, 10, 0));
    events.extend(push_fixture::response(7, 0, b"ok"));
    let mut tracker = Http3Tracker::default();
    tracker.ingest_authenticated(batch(events), 2).unwrap();
    assert_eq!(report(&tracker).pushes[0].state, MessageState::Incomplete);
    tracker
        .ingest_authenticated(
            batch(vec![header_event(
                Server,
                0,
                support::headers(&[(":status", "200")]),
            )]),
            1,
        )
        .unwrap();
    assert_eq!(report(&tracker).pushes[0].state, MessageState::Complete);
}

#[test]
fn reset_push_streams_retain_partial_body_without_claiming_completion() {
    let mut events = push_fixture::exchange();
    events.pop();
    events.push(Http3Event {
        stream_id: 7,
        sender: Server,
        event: Http3EventKind::Reset {
            final_size: 16,
            error_code: 0x10c,
        },
    });
    let mut tracker = Http3Tracker::default();
    tracker.ingest_authenticated(batch(events), 1).unwrap();
    let report = report(&tracker);
    assert_eq!(report.pushes[0].state, MessageState::Incomplete);
    assert_eq!(
        report.pushes[0].streams[0]
            .response
            .as_ref()
            .unwrap()
            .body_bytes(),
        2
    );
}

#[test]
fn promise_and_cancellation_identifiers_share_a_bounded_connection_budget() {
    let mut tracker = Http3Tracker::default();
    let events = (0..128)
        .map(|id| push_fixture::promise(0, id * 10, id))
        .collect();
    tracker.ingest_authenticated(batch(events), 1).unwrap();
    assert!(
        tracker
            .ingest_authenticated(batch(vec![push_fixture::promise(0, 1280, 128)]), 2)
            .is_err()
    );
    let report = report(&tracker);
    assert_eq!(report.pushes.len(), 128);
    assert!(
        report
            .limitations
            .iter()
            .any(|text| text.contains("incomplete"))
    );
}

#[test]
fn a_promise_after_a_successful_connect_is_not_a_valid_push() {
    let mut events = push_fixture::credit(0);
    events.push(header_event(
        Client,
        0,
        support::headers(&[(":method", "CONNECT"), (":authority", "proxy.test:443")]),
    ));
    events.push(header_event(
        Server,
        0,
        support::headers(&[(":status", "200")]),
    ));
    events.push(push_fixture::promise(0, 10, 0));
    events.extend(push_fixture::response(7, 0, b"ok"));
    let mut tracker = Http3Tracker::default();
    tracker.ingest_authenticated(batch(events), 1).unwrap();
    let report = report(&tracker);
    assert_eq!(report.pushes[0].state, MessageState::Ambiguous);
    assert_eq!(
        report.transactions[0].response.as_ref().unwrap().state,
        MessageState::Ambiguous
    );
    assert_eq!(
        report.pushes[0].streams[0]
            .response
            .as_ref()
            .unwrap()
            .body_bytes(),
        2
    );
}
