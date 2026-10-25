use super::super::{HttpHeader, MessageState};
use super::*;

pub(super) fn conversation(id: &str, connection: &Connection) -> Http3Conversation {
    let mut report = Http3Conversation {
        connection_id: id.into(), transactions: Vec::new(), control_streams: control::inspect(connection),
        limitations: vec!["QUIC authentication, connection identity, and QPACK state are supplied by the configured helper; ciphertext is not decoded by Packrat.".into(),
            "Server push is not reconstructed. Offsets refer to authenticated stream plaintext, not capture bytes; control status describes the retained prefix, not a completed connection.".into(),
            "Packet references identify helper frame-completion observations, not every fragment. Packet lookup retains the latest 4096 packet numbers.".into()],
    };
    if connection.limited {
        report
            .limitations
            .push("Retention or rejected input limits make this connection incomplete.".into());
    }
    for (stream_id, halves) in connection.streams.iter().filter(|(id, _)| **id % 4 == 0) {
        let (request, _) = halves
            .get(&Http3Sender::Client)
            .map(|half| message(half, true, false, false, connection.limited))
            .unwrap_or_default();
        let head = request
            .as_ref()
            .is_some_and(|request| request.header(":method") == Some(b"HEAD"));
        let connect = request
            .as_ref()
            .is_some_and(|request| request.header(":method") == Some(b"CONNECT"));
        let (response, interim_responses) = halves
            .get(&Http3Sender::Server)
            .map(|half| message(half, false, head, connect, connection.limited))
            .unwrap_or_default();
        report.transactions.push(Http3Exchange {
            stream_id: *stream_id,
            request,
            response,
            interim_responses,
        });
    }
    report
}

fn message(
    half: &HalfStream,
    request: bool,
    head: bool,
    connect: bool,
    connection_limited: bool,
) -> (Option<Http3Message>, Vec<Http3Message>) {
    let mut message = Http3Message::default();
    let mut interim = Vec::new();
    let mut expected = 0;
    let mut trailers = false;
    let mut ambiguous = half.ambiguous;
    let mut limited = connection_limited || half.limited;
    for (offset, frame) in &half.frames {
        if *offset != expected {
            diagnostic(
                &mut message,
                "Missing plaintext frame range; later events are not interpreted across the gap",
            );
            break;
        }
        expected += frame.length;
        retain_packets(&mut message, &frame.packets, &mut limited);
        match &frame.event {
            Http3EventKind::Headers { headers, .. } => {
                if message.headers.is_empty() {
                    if let Err(error) = validate_headers(headers, request, false) {
                        ambiguous = true;
                        diagnostic(&mut message, &error);
                    }
                    let informational = !request && status(headers).is_some_and(|code| code < 200);
                    if informational {
                        let mut response = Http3Message {
                            headers: headers.clone(),
                            state: MessageState::Complete,
                            packet_numbers: frame.packets.clone(),
                            ..Default::default()
                        };
                        if ambiguous {
                            response.state = MessageState::Ambiguous;
                        }
                        if interim.len() < 32 {
                            interim.push(response);
                        } else {
                            limited = true;
                        }
                    } else {
                        message.headers = headers.clone();
                    }
                } else if trailers || headers.iter().any(|header| header.name.starts_with(':')) {
                    ambiguous = true;
                    diagnostic(
                        &mut message,
                        "Duplicate initial headers or headers after trailers",
                    );
                } else {
                    if let Err(error) = validate_headers(headers, request, true) {
                        ambiguous = true;
                        diagnostic(&mut message, &error);
                    }
                    message.trailers = headers.clone();
                    trailers = true;
                }
            }
            Http3EventKind::Data { data, .. } => {
                if message.headers.is_empty() || trailers {
                    ambiguous = true;
                    diagnostic(
                        &mut message,
                        "DATA before initial headers or after trailers",
                    );
                } else {
                    message.body.push(Http3BodyChunk {
                        frame_offset: *offset,
                        data: data.clone(),
                        packet_numbers: frame.packets.clone(),
                    });
                }
            }
            Http3EventKind::Extension { frame_type, .. } => {
                if *frame_type == 5 {
                    limited = true;
                    diagnostic(&mut message, "PUSH_PROMISE metadata was not reconstructed");
                }
            }
            _ => {
                ambiguous = true;
                diagnostic(&mut message, "Unexpected HTTP/3 frame in a message");
            }
        }
    }
    retain_packets(&mut message, &half.final_packets, &mut limited);
    message.packet_numbers.sort_unstable();
    message.reset_code = half.reset_code;
    message.end_stream = half.final_size == Some(expected) && half.reset_code.is_none();
    if message.headers.is_empty() {
        diagnostic(
            &mut message,
            "Initial request or final response headers not captured",
        );
    }
    if half.final_size.is_none() {
        diagnostic(&mut message, "QUIC FIN not captured");
    } else if half.final_size != Some(expected) {
        diagnostic(
            &mut message,
            "Captured frame ranges do not cover the declared final size",
        );
    }
    if half.reset_code.is_some() {
        diagnostic(&mut message, "QUIC request direction was reset");
    }
    if half.ambiguous {
        diagnostic(
            &mut message,
            "Conflicting retransmission, overlapping frame ranges, or inconsistent final size",
        );
    }
    if limited {
        diagnostic(
            &mut message,
            "Retained events or packet provenance are incomplete",
        );
    }
    let tunnel = message.header(":method") == Some(b"CONNECT")
        || connect && status(&message.headers).is_some_and(|code| (200..300).contains(&code));
    let no_body = !request
        && (head || status(&message.headers).is_some_and(|code| matches!(code, 204 | 304)));
    if no_body && message.body_bytes() != 0 {
        ambiguous = true;
        diagnostic(&mut message, "Response semantics forbid a message body");
    }
    if let Err(error) = validate_content_length(&message, no_body) {
        ambiguous = true;
        diagnostic(&mut message, error);
    }
    message.state = if ambiguous {
        MessageState::Ambiguous
    } else if tunnel {
        diagnostic(
            &mut message,
            "CONNECT tunnel semantics are not reconstructed",
        );
        MessageState::Unsupported
    } else if message.end_stream
        && !message.headers.is_empty()
        && !limited
        && message.diagnostics.is_empty()
    {
        MessageState::Complete
    } else {
        MessageState::Incomplete
    };
    (Some(message), interim)
}

fn validate_headers(headers: &[HttpHeader], request: bool, trailers: bool) -> Result<(), String> {
    super::super::http2_headers::validate(headers, request, trailers)?;
    if trailers {
        if headers
            .iter()
            .any(|header| matches!(header.name.as_str(), "content-length" | "host"))
        {
            return Err("HTTP/3 framing or routing field in trailers".into());
        }
        return Ok(());
    }
    if headers
        .iter()
        .any(|header| header.name.starts_with(':') && header.value.is_empty())
    {
        return Err("Empty HTTP/3 pseudo-header value".into());
    }
    if request {
        let method = headers
            .iter()
            .find(|header| header.name == ":method")
            .ok_or("Missing :method")?;
        if !method
            .value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte))
        {
            return Err("Invalid HTTP method token".into());
        }
        let connect = headers
            .iter()
            .any(|header| header.name == ":method" && header.value == b"CONNECT");
        let extended = headers.iter().any(|header| header.name == ":protocol");
        if extended && !connect {
            return Err(":protocol requires CONNECT".into());
        }
        if extended
            && [":scheme", ":path"]
                .iter()
                .any(|required| !headers.iter().any(|header| header.name == *required))
        {
            return Err("Extended CONNECT is missing :scheme or :path".into());
        }
        if connect
            && !extended
            && headers
                .iter()
                .any(|header| matches!(header.name.as_str(), ":scheme" | ":path"))
        {
            return Err("Ordinary CONNECT must not contain :scheme or :path".into());
        }
    } else if status(headers).is_some_and(|code| code < 200 || code == 204)
        && headers.iter().any(|header| header.name == "content-length")
    {
        return Err("Content-Length is forbidden in informational and 204 responses".into());
    }
    Ok(())
}

fn status(headers: &[HttpHeader]) -> Option<u16> {
    let bytes = &headers
        .iter()
        .find(|header| header.name == ":status")?
        .value;
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

fn validate_content_length(message: &Http3Message, no_body: bool) -> Result<(), &'static str> {
    let mut value = None;
    for header in message
        .headers
        .iter()
        .filter(|header| header.name == "content-length")
    {
        if header.value.is_empty() || !header.value.iter().all(u8::is_ascii_digit) {
            return Err("Invalid HTTP/3 Content-Length");
        }
        let length: u64 = std::str::from_utf8(&header.value)
            .ok()
            .and_then(|value| value.parse().ok())
            .ok_or("Content-Length overflow")?;
        if value.is_some_and(|prior| prior != length) {
            return Err("Conflicting HTTP/3 Content-Length fields");
        }
        value = Some(length);
    }
    if !no_body
        && message.end_stream
        && value.is_some_and(|length| length != message.body_bytes() as u64)
    {
        return Err("HTTP/3 Content-Length disagrees with captured body");
    }
    Ok(())
}

fn diagnostic(message: &mut Http3Message, detail: &str) {
    if message.diagnostics.len() < 16 && !message.diagnostics.iter().any(|prior| prior == detail) {
        message.diagnostics.push(detail.into());
    }
}

fn retain_packets(message: &mut Http3Message, packets: &[u64], limited: &mut bool) {
    for number in packets {
        if !message.packet_numbers.contains(number) {
            if message.packet_numbers.len() < 256 {
                message.packet_numbers.push(*number);
            } else {
                *limited = true;
            }
        }
    }
}
