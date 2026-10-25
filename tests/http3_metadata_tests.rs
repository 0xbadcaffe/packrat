#[path = "support/http3_control.rs"]
mod control;
#[path = "support/http3_push.rs"]
mod push_fixture;
#[path = "support/http3.rs"]
mod support;
use Http3Sender::{Client, Server};
use packrat_tui::analysis::transactions::http3::*;
use support::*;

#[test]
fn a_large_push_id_cannot_fit_inside_a_two_byte_stream_prefix() {
    let event = Http3Event {
        stream_id: 7,
        sender: Server,
        event: Http3EventKind::PushStart {
            wire_length: 2,
            push_id: 64,
        },
    };
    assert!(
        Http3Tracker::default()
            .ingest_authenticated(batch(vec![event]), 1)
            .is_err()
    );
    for id in [
        0,
        63,
        64,
        16383,
        16384,
        (1 << 30) - 1,
        1 << 30,
        (1 << 62) - 1,
    ] {
        let event = push_fixture::start(7, id);
        Http3Tracker::default()
            .ingest_authenticated(batch(vec![event]), 1)
            .unwrap();
    }
}

#[test]
fn control_parameter_sizes_follow_quic_integer_boundaries() {
    for value in [
        0,
        63,
        64,
        16383,
        16384,
        (1 << 30) - 1,
        1 << 30,
        (1 << 62) - 1,
    ] {
        let mut tracker = Http3Tracker::default();
        let settings = control::settings(Client, 1, &[(value, value)]);
        let end = if let Http3EventKind::Settings { wire_length, .. } = settings.event {
            1 + wire_length
        } else {
            unreachable!()
        };
        tracker
            .ingest_authenticated(
                batch(vec![
                    control::start(Client),
                    settings,
                    control::credit(end, value),
                ]),
                1,
            )
            .unwrap();
        if value > 63 {
            let short = control::event(
                Client,
                Http3EventKind::MaxPushId {
                    offset: end,
                    wire_length: 3,
                    push_id: value,
                },
            );
            assert!(
                Http3Tracker::default()
                    .ingest_authenticated(batch(vec![short]), 1)
                    .is_err()
            );
        }
    }
}

#[test]
fn data_length_prefixes_cannot_understate_the_plaintext_frame_size() {
    for size in [0usize, 63, 64, 16383, 16384, 65536] {
        let event = data_event(Client, 0, &vec![0u8; size]);
        Http3Tracker::default()
            .ingest_authenticated(batch(vec![event]), 1)
            .unwrap();
        if size > 63 {
            let event = Http3Event {
                stream_id: 0,
                sender: Client,
                event: Http3EventKind::Data {
                    offset: 0,
                    wire_length: size as u64 + 2,
                    data: vec![0u8; size].into(),
                },
            };
            assert!(
                Http3Tracker::default()
                    .ingest_authenticated(batch(vec![event]), 1)
                    .is_err()
            );
        }
    }
}

#[test]
fn settings_cannot_claim_bytes_absent_from_or_excess_to_its_parameters() {
    for event in [
        control::event(
            Client,
            Http3EventKind::Settings {
                offset: 1,
                wire_length: 4,
                entries: vec![Http3Setting {
                    identifier: 64,
                    value: 64,
                }],
            },
        ),
        control::event(
            Client,
            Http3EventKind::Settings {
                offset: 1,
                wire_length: 17,
                entries: vec![],
            },
        ),
        Http3Event {
            stream_id: 0,
            sender: Server,
            event: Http3EventKind::PushPromise {
                offset: 0,
                wire_length: 2,
                push_id: 0,
                headers: request(),
            },
        },
    ] {
        assert!(
            Http3Tracker::default()
                .ingest_authenticated(batch(vec![event]), 1)
                .is_err()
        );
    }
}

#[test]
fn cutoff_helper_json_for_push_and_control_events_never_panics() {
    let encoded = serde_json::to_vec(&batch(push_fixture::exchange())).unwrap();
    for cut in 0..encoded.len() {
        assert!(serde_json::from_slice::<AuthenticatedHttp3Batch>(&encoded[..cut]).is_err());
    }
    let parsed: AuthenticatedHttp3Batch = serde_json::from_slice(&encoded).unwrap();
    let mut tracker = Http3Tracker::default();
    tracker.ingest_authenticated(parsed, 1).unwrap();
    assert_eq!(report(&tracker).pushes.len(), 1);
}
