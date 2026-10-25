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
            wire_length: {
                let payload: u64 = entries
                    .iter()
                    .map(|(id, value)| {
                        super::support::integer_width(*id) + super::support::integer_width(*value)
                    })
                    .sum();
                1 + super::support::integer_width(payload) + payload
            },
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
            wire_length: 2 + super::support::integer_width(push_id),
            push_id,
        },
    )
}
pub fn goaway(sender: Http3Sender, offset: u64, identifier: u64) -> Http3Event {
    event(
        sender,
        Http3EventKind::Goaway {
            offset,
            wire_length: 2 + super::support::integer_width(identifier),
            identifier,
        },
    )
}
