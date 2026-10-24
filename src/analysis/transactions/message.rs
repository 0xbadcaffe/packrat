use super::framing::{Body, frame_body};
use super::*;

pub(super) fn request_candidate(bytes: &[u8]) -> bool {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    let _ = request.parse(&bytes[..bytes.len().min(MAX_HEADER_BYTES)]);
    request.method.is_some()
}

pub(super) fn request(
    stream: &ReassembledStream,
    direction: Direction,
    start: usize,
) -> HttpMessage {
    let data = direction.bytes(stream);
    let window = &data[start..data.len().min(start.saturating_add(MAX_HEADER_BYTES))];
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    let parsed = request.parse(window);
    let mut message = empty(direction, start);
    message.method = request.method.map(str::to_string);
    message.target = request.path.map(str::to_string);
    finish(stream, data, parsed, request.headers, message, true, false)
}

pub(super) fn response(
    stream: &ReassembledStream,
    direction: Direction,
    start: usize,
    method: &str,
) -> HttpMessage {
    let data = direction.bytes(stream);
    let window = &data[start..data.len().min(start.saturating_add(MAX_HEADER_BYTES))];
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    let parsed = response.parse(window);
    let mut message = empty(direction, start);
    message.status = response.code;
    let no_body = method == "HEAD"
        || response
            .code
            .is_some_and(|code| code < 200 || code == 204 || code == 304)
        || (method == "CONNECT" && response.code.is_some_and(|code| (200..300).contains(&code)));
    finish(
        stream,
        data,
        parsed,
        response.headers,
        message,
        false,
        no_body,
    )
}

fn empty(direction: Direction, start: usize) -> HttpMessage {
    HttpMessage {
        method: None,
        target: None,
        status: None,
        span: ByteSpan {
            direction,
            start,
            end: start,
        },
        header_end: start,
        body: Vec::new(),
        headers: Vec::new(),
        trailers: Vec::new(),
        state: MessageState::Incomplete,
        diagnostic: None,
        packet_numbers: Vec::new(),
        completion_packet: None,
    }
}

fn finish(
    stream: &ReassembledStream,
    data: &[u8],
    parsed: httparse::Result<usize>,
    headers: &[httparse::Header<'_>],
    mut message: HttpMessage,
    request: bool,
    no_body: bool,
) -> HttpMessage {
    let start = message.span.start;
    let direction = message.span.direction;
    message.headers = headers
        .iter()
        .filter(|header| !header.name.is_empty())
        .map(|header| HttpHeader {
            name: header.name.into(),
            value: header.value.to_vec(),
        })
        .collect();
    match parsed {
        Ok(httparse::Status::Complete(length)) => {
            message.header_end = start + length;
            let finished = if direction.from_a() {
                stream.client_finished
            } else {
                stream.server_finished
            };
            let eof = finished && !stream.reset && !stream.has_gaps();
            let body = if !request
                && !message
                    .status
                    .is_some_and(|status| (100..600).contains(&status))
            {
                Body {
                    state: MessageState::Ambiguous,
                    diagnostic: Some("HTTP status code is outside 100..599".into()),
                    ..Body::complete(message.header_end)
                }
            } else if strict_crlf(&data[start..message.header_end]) {
                frame_body(data, message.header_end, headers, no_body, request, eof)
            } else {
                Body {
                    state: MessageState::Ambiguous,
                    diagnostic: Some("Non-CRLF HTTP framing".into()),
                    ..Body::complete(message.header_end)
                }
            };
            message.span.end = body.end;
            message.state = body.state;
            message.diagnostic = body.diagnostic;
            message.trailers = body.trailers;
            message.body = body
                .spans
                .into_iter()
                .map(|range| ByteSpan {
                    direction,
                    start: range.start,
                    end: range.end,
                })
                .collect();
            if body.eof_delimited && body.state == MessageState::Complete {
                message.completion_packet = if direction.from_a() {
                    stream.client_fin_packet
                } else {
                    stream.server_fin_packet
                };
            }
        }
        Ok(httparse::Status::Partial) => {
            message.span.end = data.len().min(start.saturating_add(MAX_HEADER_BYTES));
            message.header_end = message.span.end;
            if data.len() - start >= MAX_HEADER_BYTES {
                message.state = MessageState::Unsupported;
            }
            message.diagnostic = Some("HTTP header incomplete or over reconstruction limit".into());
        }
        Err(error) => {
            message.span.end = data.len().min(start.saturating_add(MAX_HEADER_BYTES));
            message.header_end = message.span.end;
            message.state = MessageState::Ambiguous;
            message.diagnostic = Some(format!("Invalid HTTP header: {error}"));
        }
    }
    message.packet_numbers = stream.packet_numbers(direction.from_a(), start, message.span.end);
    if let Some(packet) = message.completion_packet {
        if !message.packet_numbers.contains(&packet) {
            message.packet_numbers.push(packet);
            message.packet_numbers.sort_unstable();
        }
    }
    message
}

fn strict_crlf(bytes: &[u8]) -> bool {
    bytes.windows(4).last() == Some(b"\r\n\r\n")
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| *byte != b'\n' || index > 0 && bytes[index - 1] == b'\r')
}
