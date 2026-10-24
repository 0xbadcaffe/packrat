#![allow(dead_code)]

#[path = "packets.rs"]
mod packets;

use packrat_tui::analysis::stream::ReassembledStream;
use packrat_tui::analysis::transactions::{HttpConversation, HttpMessage, reconstruct_http};
use packrat_tui::net::{packet::Packet, parser::parse_ethernet};

pub fn stream(request: &[u8], response: &[u8]) -> ReassembledStream {
    let mut stream = ReassembledStream::default();
    stream.client_data = request.to_vec();
    stream.server_data = response.to_vec();
    stream
}

pub fn conversation(request: &[u8], response: &[u8]) -> HttpConversation {
    reconstruct_http(&stream(request, response))
}

pub fn body(stream: &ReassembledStream, message: &HttpMessage) -> Vec<u8> {
    message
        .body
        .iter()
        .flat_map(|span| {
            span.direction.bytes(stream)[span.start..span.end]
                .iter()
                .copied()
        })
        .collect()
}

pub fn tcp(no: u64, sequence: u32, flags: u8, payload: &[u8], reverse: bool) -> Packet {
    let packet = packets::tcp(no, sequence, flags, payload);
    if !reverse {
        return packet;
    }
    let mut bytes = packet.bytes.to_vec();
    for index in 0..4 {
        bytes.swap(26 + index, 30 + index);
    }
    for index in 0..2 {
        bytes.swap(34 + index, 36 + index);
    }
    parse_ethernet(&bytes, no, no as f64)
}
