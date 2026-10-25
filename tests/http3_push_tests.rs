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
fn promised_request_and_pushed_response_share_a_push_id_not_a_stream_id() {
    let mut tracker = Http3Tracker::default();
    tracker
        .ingest_authenticated(batch(push_fixture::exchange()), 1)
        .unwrap();
    let report = report(&tracker);
    assert_eq!(report.pushes.len(), 1);
    let push = &report.pushes[0];
    assert_eq!(push.push_id, 0);
    assert_eq!(push.promised_on, [0]);
    assert_eq!(push.promise_packets, [1]);
    assert_eq!(push.streams[0].stream_id, 7);
    assert_eq!(
        push.streams[0].response.as_ref().unwrap().body[0]
            .data
            .as_ref(),
        b"ok"
    );
    assert_eq!(push.state, MessageState::Complete);
    assert!(report.unclassified_streams.is_empty());
}

#[test]
fn push_response_before_its_promise_or_credit_remains_incomplete_until_correlated() {
    let mut tracker = Http3Tracker::default();
    tracker
        .ingest_authenticated(batch(push_fixture::response(7, 0, b"ok")), 3)
        .unwrap();
    assert_eq!(report(&tracker).pushes[0].state, MessageState::Incomplete);
    tracker
        .ingest_authenticated(batch(vec![push_fixture::promise(0, 0, 0)]), 2)
        .unwrap();
    assert_eq!(report(&tracker).pushes[0].state, MessageState::Incomplete);
    tracker
        .ingest_authenticated(batch(push_fixture::credit(0)), 1)
        .unwrap();
    let report = report(&tracker);
    assert_eq!(report.pushes[0].state, MessageState::Complete);
    assert_eq!(
        report.pushes[0].streams[0]
            .response
            .as_ref()
            .unwrap()
            .packet_numbers,
        [3]
    );
}

#[test]
fn missing_push_prefix_never_causes_a_guessed_push_id() {
    let mut tracker = Http3Tracker::default();
    let mut events = push_fixture::credit(0);
    events.push(push_fixture::promise(0, 0, 0));
    events.extend(push_fixture::response(7, 0, b"ok").into_iter().skip(1));
    tracker.ingest_authenticated(batch(events), 2).unwrap();
    let partial = report(&tracker);
    assert_eq!(partial.unclassified_streams, [7]);
    assert!(partial.pushes[0].streams.is_empty());
    tracker
        .ingest_authenticated(batch(vec![push_fixture::start(7, 0)]), 1)
        .unwrap();
    assert_eq!(report(&tracker).pushes[0].state, MessageState::Complete);
}

#[test]
fn matching_repeated_promises_link_all_parents_and_conflicting_headers_remain_ambiguous() {
    let mut tracker = Http3Tracker::default();
    tracker
        .ingest_authenticated(batch(push_fixture::exchange()), 1)
        .unwrap();
    tracker
        .ingest_authenticated(batch(vec![push_fixture::promise(4, 0, 0)]), 2)
        .unwrap();
    assert_eq!(report(&tracker).pushes[0].promised_on, [0, 4]);
    assert_eq!(report(&tracker).pushes[0].state, MessageState::Complete);
    let mut changed = push_fixture::promise(8, 0, 0);
    if let Http3EventKind::PushPromise { headers, .. } = &mut changed.event {
        headers[2].value = b"/different".to_vec();
    }
    tracker
        .ingest_authenticated(batch(vec![changed]), 3)
        .unwrap();
    let report = report(&tracker);
    assert_eq!(report.pushes[0].state, MessageState::Ambiguous);
    assert_eq!(report.pushes[0].promise_packets, [1, 2, 3]);
    assert_eq!(report.pushes[0].request_headers[2].value, b"/inspect");
}

#[test]
fn duplicate_push_streams_keep_each_response_instead_of_overwriting_evidence() {
    let mut tracker = Http3Tracker::default();
    tracker
        .ingest_authenticated(batch(push_fixture::exchange()), 1)
        .unwrap();
    tracker
        .ingest_authenticated(batch(push_fixture::response(11, 0, b"different")), 2)
        .unwrap();
    let report = report(&tracker);
    let push = &report.pushes[0];
    assert_eq!(push.state, MessageState::Ambiguous);
    assert_eq!(push.streams.len(), 2);
    assert_eq!(
        push.streams[0].response.as_ref().unwrap().body[0]
            .data
            .as_ref(),
        b"ok"
    );
    assert_eq!(
        push.streams[1].response.as_ref().unwrap().body[0]
            .data
            .as_ref(),
        b"different"
    );
}

#[test]
fn late_head_promise_resolves_content_length_uncertainty_without_a_false_violation() {
    let mut tracker = Http3Tracker::default();
    let mut headers = header_event(
        Server,
        2,
        support::headers(&[(":status", "200"), ("content-length", "20")]),
    );
    headers.stream_id = 7;
    let mut finish = finished(Server, 12);
    finish.stream_id = 7;
    tracker
        .ingest_authenticated(batch(vec![push_fixture::start(7, 0), headers, finish]), 2)
        .unwrap();
    let partial = report(&tracker);
    assert_eq!(partial.pushes[0].state, MessageState::Incomplete);
    assert_eq!(
        partial.pushes[0].streams[0]
            .response
            .as_ref()
            .unwrap()
            .state,
        MessageState::Incomplete
    );
    let mut promise = push_fixture::promise(0, 0, 0);
    if let Http3EventKind::PushPromise { headers, .. } = &mut promise.event {
        headers[0].value = b"HEAD".to_vec();
    }
    let mut events = push_fixture::credit(0);
    events.push(promise);
    tracker.ingest_authenticated(batch(events), 1).unwrap();
    assert_eq!(report(&tracker).pushes[0].state, MessageState::Complete);
}

#[test]
fn cancellation_preserves_the_promised_request_and_completed_response() {
    let mut events = push_fixture::exchange();
    for sender in [Client, Server] {
        if sender == Server {
            events.extend([control::start(Server), control::settings(Server, 1, &[])]);
        }
        events.push(control::event(
            sender,
            Http3EventKind::CancelPush {
                offset: if sender == Client { 6 } else { 3 },
                wire_length: 3,
                push_id: 0,
            },
        ));
    }
    let mut tracker = Http3Tracker::default();
    tracker.ingest_authenticated(batch(events), 1).unwrap();
    let report = report(&tracker);
    assert_eq!(report.pushes[0].cancelled_by, [Client, Server]);
    assert_eq!(report.pushes[0].state, MessageState::Complete);
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
fn goaway_reports_request_and_push_cutoffs_without_claiming_bytes_disappeared() {
    let mut events = push_fixture::exchange();
    events.push(control::goaway(Client, 6, 0));
    events.extend([
        control::start(Server),
        control::settings(Server, 1, &[]),
        control::goaway(Server, 3, 4),
    ]);
    let mut next_request = header_event(Client, 0, request());
    next_request.stream_id = 4;
    events.push(next_request);
    let mut tracker = Http3Tracker::default();
    tracker.ingest_authenticated(batch(events), 1).unwrap();
    let report = report(&tracker);
    assert!(!report.transactions[0].goaway_excluded);
    assert!(report.transactions[1].goaway_excluded);
    assert!(report.pushes[0].goaway_excluded);
    assert_eq!(
        report.pushes[0].streams[0]
            .response
            .as_ref()
            .unwrap()
            .body_bytes(),
        2
    );
}
