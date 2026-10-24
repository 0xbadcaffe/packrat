#![allow(dead_code)]
use packrat_tui::analysis::transactions::{HttpHeader, http3::*};

pub fn headers(values: &[(&str, &str)]) -> Vec<HttpHeader> {
    values
        .iter()
        .map(|(name, value)| HttpHeader {
            name: (*name).into(),
            value: value.as_bytes().to_vec(),
        })
        .collect()
}
pub fn request() -> Vec<HttpHeader> {
    headers(&[
        (":method", "GET"),
        (":scheme", "https"),
        (":path", "/inspect"),
        (":authority", "example.test"),
    ])
}
pub fn header_event(sender: Http3Sender, offset: u64, values: Vec<HttpHeader>) -> Http3Event {
    Http3Event {
        stream_id: 0,
        sender,
        event: Http3EventKind::Headers {
            offset,
            wire_length: 10,
            headers: values,
        },
    }
}
pub fn data_event(sender: Http3Sender, offset: u64, bytes: &[u8]) -> Http3Event {
    Http3Event {
        stream_id: 0,
        sender,
        event: Http3EventKind::Data {
            offset,
            wire_length: bytes.len() as u64 + 2,
            data: bytes.to_vec(),
        },
    }
}
pub fn finished(sender: Http3Sender, size: u64) -> Http3Event {
    Http3Event {
        stream_id: 0,
        sender,
        event: Http3EventKind::Finished { final_size: size },
    }
}
pub fn batch(events: Vec<Http3Event>) -> AuthenticatedHttp3Batch {
    AuthenticatedHttp3Batch {
        connection_id: "authenticated-connection".into(),
        alpn: "h3".into(),
        events,
    }
}
pub fn report(tracker: &Http3Tracker) -> Http3Conversation {
    tracker.conversation("authenticated-connection").unwrap()
}
