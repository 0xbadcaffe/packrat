#![allow(dead_code)]

#[path = "packets.rs"]
mod packets;

use packrat_tui::analysis::stream::ReassembledStream;
use packrat_tui::analysis::transactions::{HttpConversation, HttpMessage, reconstruct_http};
use packrat_tui::export::pcapng::PcapNgWriter;
use packrat_tui::net::{packet::Packet, parser::parse_ethernet};
use std::path::Path;

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

#[derive(Clone, Copy)]
pub enum AuthResponseDelivery {
    Ordered,
    GapFilled,
    PrefixMissing,
    TaggedGapFilled,
    SplitTagTypes,
}

pub fn write_coalesced_auth_capture(path: &Path, delivery: AuthResponseDelivery) -> Option<u64> {
    let request = b"GET /status HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let response = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
    let mut writer = PcapNgWriter::create(path).unwrap();
    let mut write = |frame, sequence, flags, payload, reverse| {
        let mut packet = tcp(frame, sequence, flags, payload, reverse);
        if matches!(delivery, AuthResponseDelivery::TaggedGapFilled | AuthResponseDelivery::SplitTagTypes) {
            let tpid = if matches!(delivery, AuthResponseDelivery::SplitTagTypes) && frame == 8 {
                0x88a8_u16
            } else {
                0x8100_u16
            };
            let tci = if frame % 2 == 0 { 0xb014_u16 } else { 20_u16 };
            packet.bytes.splice(12..12, [tpid, tci].into_iter().flat_map(u16::to_be_bytes));
        }
        writer.write_packet(&packet).unwrap();
    };
    write(1, 100, 0x02, &[], false);
    write(2, 500, 0x12, &[], true);
    for index in 0..5 {
        write(3 + u64::from(index), 101 + index * request.len() as u32, 0x18, request, false);
    }
    let coalesced = response.repeat(5);
    let split = 7;
    let later_sequence = 501 + split as u32;
    let trigger = match delivery {
        AuthResponseDelivery::Ordered => {
            write(8, 501, 0x18, &coalesced, true);
            write(9, 501, 0x18, &coalesced, true);
            Some(8)
        }
        AuthResponseDelivery::GapFilled => {
            write(8, later_sequence, 0x18, &coalesced[split..], true);
            write(9, 501, 0x18, &coalesced[..split], true);
            write(10, later_sequence, 0x18, &coalesced[split..], true);
            Some(9)
        }
        AuthResponseDelivery::TaggedGapFilled | AuthResponseDelivery::SplitTagTypes => {
            write(8, later_sequence, 0x18, &coalesced[split..], true);
            write(9, 501, 0x18, &coalesced[..split], true);
            matches!(delivery, AuthResponseDelivery::TaggedGapFilled).then_some(9)
        }
        AuthResponseDelivery::PrefixMissing => {
            write(8, later_sequence, 0x18, &coalesced[split..], true);
            write(9, later_sequence, 0x18, &coalesced[split..], true);
            None
        }
    };
    writer.flush().unwrap();
    trigger
}
