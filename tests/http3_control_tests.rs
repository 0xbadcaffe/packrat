#[path = "support/http3_control.rs"]
mod control;
#[path = "support/http3.rs"]
mod support;
use Http3Sender::{Client, Server};
use packrat_tui::analysis::transactions::{MessageState, http3::*};
use support::*;

#[test]
fn control_streams_expose_settings_credit_goaway_and_packet_provenance() {
    let mut tracker = Http3Tracker::default();
    tracker
        .ingest_authenticated(
            batch(vec![
                control::start(Client),
                control::settings(Client, 1, &[(1, 0), (6, 60), (33, 9)]),
                control::credit(9, 5),
                control::start(Server),
                control::settings(Server, 1, &[]),
                control::goaway(Server, 3, 8),
            ]),
            1,
        )
        .unwrap();
    let report = report(&tracker);
    assert!(report.transactions.is_empty());
    assert_eq!(report.control_streams.len(), 2);
    assert_eq!(report.control_streams[0].max_push_id, Some(5));
    assert_eq!(report.control_streams[0].settings[2].identifier, 33);
    assert_eq!(report.control_streams[1].goaway, Some(8));
    assert!(
        report
            .control_streams
            .iter()
            .all(|stream| stream.state == MessageState::Complete && stream.packet_numbers == [1])
    );
}

#[test]
fn control_reordering_does_not_guess_across_a_missing_prefix() {
    let mut tracker = Http3Tracker::default();
    tracker
        .ingest_authenticated(batch(vec![control::credit(3, 1)]), 3)
        .unwrap();
    assert_eq!(
        report(&tracker).control_streams[0].state,
        MessageState::Incomplete
    );
    tracker
        .ingest_authenticated(batch(vec![control::settings(Client, 1, &[])]), 2)
        .unwrap();
    assert_eq!(
        report(&tracker).control_streams[0].state,
        MessageState::Incomplete
    );
    tracker
        .ingest_authenticated(batch(vec![control::start(Client)]), 1)
        .unwrap();
    let report = report(&tracker);
    assert_eq!(report.control_streams[0].state, MessageState::Complete);
    assert_eq!(report.control_streams[0].packet_numbers, [1, 2, 3]);
}

#[test]
fn missing_or_duplicate_settings_and_forbidden_settings_are_reported() {
    for events in [
        vec![control::start(Client), control::credit(1, 1)],
        vec![
            control::start(Client),
            control::settings(Client, 1, &[]),
            control::settings(Client, 3, &[]),
        ],
        vec![
            control::start(Client),
            control::settings(Client, 1, &[(1, 0), (1, 1)]),
        ],
        vec![
            control::start(Client),
            control::settings(Client, 1, &[(2, 0)]),
        ],
        vec![
            control::start(Client),
            control::settings(Client, 1, &[(8, 2)]),
        ],
        vec![
            control::start(Client),
            control::settings(Client, 1, &[(0x33, 2)]),
        ],
    ] {
        let mut tracker = Http3Tracker::default();
        tracker.ingest_authenticated(batch(events), 1).unwrap();
        let report = report(&tracker);
        assert_eq!(report.control_streams[0].state, MessageState::Ambiguous);
        assert!(!report.control_streams[0].diagnostics.is_empty());
    }
}

#[test]
fn goaway_and_push_credit_are_monotonic_in_control_stream_order() {
    for events in [
        vec![
            control::start(Server),
            control::settings(Server, 1, &[]),
            control::goaway(Server, 3, 8),
            control::goaway(Server, 6, 12),
        ],
        vec![
            control::start(Server),
            control::settings(Server, 1, &[]),
            control::goaway(Server, 3, 3),
        ],
        vec![
            control::start(Client),
            control::settings(Client, 1, &[]),
            control::credit(3, 5),
            control::credit(6, 4),
        ],
        vec![
            control::start(Server),
            control::settings(Server, 1, &[]),
            control::event(
                Server,
                Http3EventKind::MaxPushId {
                    offset: 3,
                    wire_length: 3,
                    push_id: 0,
                },
            ),
        ],
    ] {
        let mut tracker = Http3Tracker::default();
        tracker.ingest_authenticated(batch(events), 1).unwrap();
        assert_eq!(
            report(&tracker).control_streams[0].state,
            MessageState::Ambiguous
        );
    }
    let mut tracker = Http3Tracker::default();
    tracker
        .ingest_authenticated(
            batch(vec![
                control::start(Server),
                control::settings(Server, 1, &[]),
                control::goaway(Server, 6, 4),
                control::goaway(Server, 3, 8),
            ]),
            1,
        )
        .unwrap();
    assert_eq!(
        report(&tracker).control_streams[0].state,
        MessageState::Complete
    );
    assert_eq!(report(&tracker).control_streams[0].goaway, Some(4));
}

#[test]
fn closing_a_control_stream_or_creating_two_control_streams_is_a_violation() {
    for reset in [false, true] {
        let mut tracker = Http3Tracker::default();
        let close = if reset {
            Http3EventKind::Reset {
                final_size: 3,
                error_code: 0,
            }
        } else {
            Http3EventKind::Finished { final_size: 3 }
        };
        tracker
            .ingest_authenticated(
                batch(vec![
                    control::start(Client),
                    control::settings(Client, 1, &[]),
                    control::event(Client, close),
                ]),
                1,
            )
            .unwrap();
        assert!(
            report(&tracker).control_streams[0]
                .diagnostics
                .iter()
                .any(|text| text.contains("closed or reset"))
        );
    }
    let mut tracker = Http3Tracker::default();
    let mut another = control::start(Client);
    another.stream_id = 6;
    tracker
        .ingest_authenticated(batch(vec![control::start(Client), another]), 1)
        .unwrap();
    assert!(
        report(&tracker)
            .control_streams
            .iter()
            .all(|stream| stream.state == MessageState::Ambiguous)
    );
}

#[test]
fn control_input_bounds_and_sender_ownership_are_validated_before_retention() {
    for event in [
        Http3Event {
            stream_id: 3,
            ..control::start(Client)
        },
        Http3Event {
            stream_id: 0,
            ..control::start(Client)
        },
        control::event(Client, Http3EventKind::ControlStart { wire_length: 3 }),
        control::settings(Client, 1, &vec![(1, 0); 129]),
        control::event(
            Client,
            Http3EventKind::Goaway {
                offset: 1,
                wire_length: 3,
                identifier: u64::MAX,
            },
        ),
    ] {
        let mut tracker = Http3Tracker::default();
        assert!(tracker.ingest_authenticated(batch(vec![event]), 1).is_err());
        assert_eq!(tracker.connection_ids().count(), 0);
    }
}

#[test]
fn data_on_a_control_stream_is_a_policy_violation_not_a_parser_panic() {
    let mut data = data_event(Client, 3, b"no");
    data.stream_id = 2;
    let mut tracker = Http3Tracker::default();
    tracker
        .ingest_authenticated(
            batch(vec![
                control::start(Client),
                control::settings(Client, 1, &[]),
                data,
            ]),
            1,
        )
        .unwrap();
    assert_eq!(
        report(&tracker).control_streams[0].state,
        MessageState::Ambiguous
    );
}

#[test]
fn an_unknown_stream_prefix_is_not_proof_of_a_second_control_stream() {
    let mut partial = control::settings(Client, 1, &[]);
    partial.stream_id = 6;
    let mut tracker = Http3Tracker::default();
    tracker
        .ingest_authenticated(
            batch(vec![
                control::start(Client),
                control::settings(Client, 1, &[]),
                partial,
            ]),
            1,
        )
        .unwrap();
    let report = report(&tracker);
    assert_eq!(report.control_streams[0].state, MessageState::Complete);
    assert_eq!(report.control_streams[1].state, MessageState::Incomplete);
}

#[test]
fn the_observation_closing_a_critical_stream_is_preserved_in_evidence() {
    let mut tracker = Http3Tracker::default();
    tracker
        .ingest_authenticated(
            batch(vec![
                control::start(Client),
                control::settings(Client, 1, &[]),
            ]),
            1,
        )
        .unwrap();
    tracker
        .ingest_authenticated(
            batch(vec![control::event(
                Client,
                Http3EventKind::Finished { final_size: 3 },
            )]),
            2,
        )
        .unwrap();
    assert_eq!(report(&tracker).control_streams[0].packet_numbers, [1, 2]);
}
