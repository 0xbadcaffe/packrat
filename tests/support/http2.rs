#![allow(dead_code)]
use packrat_tui::analysis::stream::ReassembledStream;

pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub fn frame(kind: u8, flags: u8, id: u32, payload: &[u8]) -> Vec<u8> {
    let length = payload.len() as u32;
    let mut bytes = length.to_be_bytes()[1..].to_vec();
    bytes.extend([kind, flags]);
    bytes.extend(id.to_be_bytes());
    bytes.extend(payload);
    bytes
}

pub fn stream(client: &[u8], server: &[u8]) -> ReassembledStream {
    let mut stream = ReassembledStream::default();
    stream.client_data = PREFACE.to_vec();
    stream.client_data.extend(frame(4, 0, 0, &[]));
    stream.client_data.extend(client);
    stream.server_data = frame(4, 0, 0, &[]);
    stream.server_data.extend(server);
    stream
}

pub fn headers(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
    loona_hpack::Encoder::new().encode(fields.iter().copied())
}

pub fn request(path: &[u8]) -> Vec<u8> {
    headers(&[
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":path", path),
    ])
}
