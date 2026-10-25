#![allow(dead_code)]
use packrat_tui::analysis::transactions::http3::*;

pub fn event(sender: Http3Sender, event: Http3EventKind) -> Http3Event {
    Http3Event {
        stream_id: if sender == Http3Sender::Client { 2 } else { 3 },
        sender,
        event,
    }
}
pub fn start(sender: Http3Sender) -> Http3Event {
    event(sender, Http3EventKind::ControlStart { wire_length: 1 })
}
pub fn settings(sender: Http3Sender, offset: u64, entries: &[(u64, u64)]) -> Http3Event {
    event(
        sender,
        Http3EventKind::Settings {
            offset,
            wire_length: 2 + entries.len() as u64 * 2,
            entries: entries
                .iter()
                .map(|(identifier, value)| Http3Setting {
                    identifier: *identifier,
                    value: *value,
                })
                .collect(),
        },
    )
}
pub fn credit(offset: u64, push_id: u64) -> Http3Event {
    event(
        Http3Sender::Client,
        Http3EventKind::MaxPushId {
            offset,
            wire_length: 3,
            push_id,
        },
    )
}
pub fn goaway(sender: Http3Sender, offset: u64, identifier: u64) -> Http3Event {
    event(
        sender,
        Http3EventKind::Goaway {
            offset,
            wire_length: 3,
            identifier,
        },
    )
}
