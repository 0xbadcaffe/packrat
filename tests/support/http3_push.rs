#![allow(dead_code)]
use super::{control, support};
use Http3Sender::{Client, Server};
use packrat_tui::analysis::transactions::http3::*;

pub fn credit(maximum: u64) -> Vec<Http3Event> {
    vec![
        control::start(Client),
        control::settings(Client, 1, &[]),
        control::credit(3, maximum),
    ]
}
pub fn promise(parent: u64, offset: u64, push_id: u64) -> Http3Event {
    Http3Event {
        stream_id: parent,
        sender: Server,
        event: Http3EventKind::PushPromise {
            offset,
            wire_length: 10,
            push_id,
            headers: support::request(),
        },
    }
}
pub fn start(stream_id: u64, push_id: u64) -> Http3Event {
    Http3Event {
        stream_id,
        sender: Server,
        event: Http3EventKind::PushStart {
            wire_length: 2,
            push_id,
        },
    }
}
pub fn response(stream_id: u64, push_id: u64, body: &[u8]) -> Vec<Http3Event> {
    let mut headers = support::header_event(
        Server,
        2,
        support::headers(&[
            (":status", "200"),
            ("content-length", &body.len().to_string()),
        ]),
    );
    headers.stream_id = stream_id;
    let mut data = support::data_event(Server, 12, body);
    data.stream_id = stream_id;
    let mut finish = support::finished(Server, 14 + body.len() as u64);
    finish.stream_id = stream_id;
    vec![start(stream_id, push_id), headers, data, finish]
}
pub fn exchange() -> Vec<Http3Event> {
    let mut events = credit(0);
    events.push(promise(0, 0, 0));
    events.extend(response(7, 0, b"ok"));
    events
}
