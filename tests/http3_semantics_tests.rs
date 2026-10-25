#[path = "support/http3.rs"]
mod support;
use Http3Sender::{Client, Server};
use packrat_tui::analysis::transactions::{MessageState, http3::*};
use support::*;

#[test]
fn successful_connect_tunnels_are_not_misreported_as_http_response_bodies() {
    let mut tracker = Http3Tracker::default();
    tracker
        .ingest_authenticated(
            batch(vec![
                header_event(
                    Client,
                    0,
                    headers(&[(":method", "CONNECT"), (":authority", "example.test:443")]),
                ),
                finished(Client, 10),
                header_event(Server, 0, headers(&[(":status", "200")])),
                data_event(Server, 10, b"tunnel"),
                finished(Server, 18),
            ]),
            1,
        )
        .unwrap();
    let report = report(&tracker);
    assert_eq!(
        report.transactions[0].request.as_ref().unwrap().state,
        MessageState::Unsupported
    );
    assert_eq!(
        report.transactions[0].response.as_ref().unwrap().state,
        MessageState::Unsupported
    );
}

#[test]
fn forbidden_content_length_in_informational_and_204_responses_is_ambiguous() {
    for status in ["103", "204"] {
        let mut tracker = Http3Tracker::default();
        tracker
            .ingest_authenticated(
                batch(vec![
                    header_event(
                        Server,
                        0,
                        headers(&[(":status", status), ("content-length", "0")]),
                    ),
                    finished(Server, 10),
                ]),
                1,
            )
            .unwrap();
        let report = report(&tracker);
        let exchange = &report.transactions[0];
        let message = if status == "103" {
            &exchange.interim_responses[0]
        } else {
            exchange.response.as_ref().unwrap()
        };
        assert_eq!(message.state, MessageState::Ambiguous);
    }
}

#[test]
fn malformed_extended_connect_and_non_token_methods_are_ambiguous() {
    for fields in [
        headers(&[
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":authority", "example.test"),
        ]),
        headers(&[(":method", "GE T"), (":scheme", "https"), (":path", "/")]),
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
fn trailers_are_not_permitted_inside_a_successful_connect_tunnel() {
    let mut tracker = Http3Tracker::default();
    tracker
        .ingest_authenticated(
            batch(vec![
                header_event(
                    Client,
                    0,
                    headers(&[(":method", "CONNECT"), (":authority", "example.test:443")]),
                ),
                header_event(Server, 0, headers(&[(":status", "200")])),
                header_event(Server, 10, headers(&[("checksum", "not-a-trailer")])),
                finished(Server, 20),
            ]),
            1,
        )
        .unwrap();
    let report = report(&tracker);
    assert_eq!(
        report.transactions[0].response.as_ref().unwrap().state,
        MessageState::Ambiguous
    );
}
