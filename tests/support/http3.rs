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
            data: bytes.into(),
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

pub fn quic_packet(number: u64) -> packrat_tui::net::packet::Packet {
    let payload = [0xc0, 0, 0, 0, 1, 4, 1, 2, 3, 4, 4, 5, 6, 7, 8, 0];
    let mut bytes = vec![0u8; 42];
    bytes[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
    bytes[22] = 64;
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(&[192, 0, 2, 1]);
    bytes[30..34].copy_from_slice(&[192, 0, 2, 2]);
    bytes[34..36].copy_from_slice(&40_000u16.to_be_bytes());
    bytes[36..38].copy_from_slice(&443u16.to_be_bytes());
    bytes[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    bytes.extend_from_slice(&payload);
    packrat_tui::net::parser::parse_ethernet(&bytes, number, number as f64)
}

#[cfg(unix)]
pub fn helper(directory: &std::path::Path, response: &serde_json::Value) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = directory.join("quic-helper.sh");
    let response = serde_json::to_string(response)
        .unwrap()
        .replace('\'', "'\\''");
    std::fs::write(
        &path,
        format!("#!/bin/sh\nwhile IFS= read -r line; do printf '%s\\n' '{response}'; done\n"),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}
