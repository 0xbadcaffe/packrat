use super::http2_headers::{HeadersDecoder, validate};
use super::http2_wire::{Frame, PREFACE, frames, unpad};
use super::*;
use std::collections::BTreeMap;

struct HeaderBlock {
    id: u32,
    promised_by: Option<u32>,
    bytes: Vec<u8>,
    packets: Vec<u64>,
    end_stream: bool,
}

/// Decode retained cleartext HTTP/2. No TLS or QUIC ciphertext is interpreted.
pub fn reconstruct_http2(stream: &ReassembledStream) -> MultiplexedConversation {
    let mut report = MultiplexedConversation {
        protocol: MultiplexedProtocol::Http2,
        transactions: Vec::new(),
        limitations: Vec::new(),
        goaway_stream: None,
    };
    let client = if stream.client_data.starts_with(PREFACE) {
        Direction::AtoB
    } else if stream.server_data.starts_with(PREFACE) {
        Direction::BtoA
    } else {
        report
            .limitations
            .push("HTTP/2 client preface is not retained; HPACK context is unknown".into());
        return report;
    };
    if stream.has_gaps() || stream.reset {
        report.limitations.push(
            "TCP gaps, discarded bytes, ambiguous epoch, or reset limit reconstruction".into(),
        );
    }
    let client_frames = frames(stream, client, PREFACE.len(), &mut report.limitations);
    let server_frames = frames(stream, client.reverse(), 0, &mut report.limitations);
    let mut transactions = BTreeMap::new();
    for (request, frames, peer) in [
        (true, &client_frames, &server_frames),
        (false, &server_frames, &client_frames),
    ] {
        let limit = table_limit(peer, &mut report.limitations);
        decode_direction(request, frames, limit, &mut transactions, &mut report);
    }
    for transaction in transactions.values_mut() {
        let no_body = transaction
            .request
            .as_ref()
            .is_some_and(|message| message.header(":method") == Some(b"HEAD"))
            || transaction
                .response
                .as_ref()
                .is_some_and(|message| matches!(message.header(":status"), Some(b"204" | b"304")));
        finish_message(
            transaction.request.as_mut(),
            transaction.reset_code,
            stream.has_gaps(),
            false,
        );
        finish_message(
            transaction.response.as_mut(),
            transaction.reset_code,
            stream.has_gaps(),
            no_body,
        );
    }
    report.transactions = transactions.into_values().collect();
    report
}

fn table_limit(frames: &[Frame<'_>], limitations: &mut Vec<String>) -> usize {
    let mut limit = None;
    let mut updates = 0;
    for frame in frames
        .iter()
        .filter(|frame| frame.kind == 4 && frame.flags & 1 == 0)
    {
        for setting in frame.payload.chunks_exact(6) {
            if setting[..2] == [0, 1] {
                let value = u32::from_be_bytes(setting[2..].try_into().unwrap()) as usize;
                limit = Some(limit.map_or(value, |old: usize| old.max(value)));
                updates += 1;
            }
        }
    }
    let limit = limit.unwrap_or(4096);
    if limit > MAX_HEADER_BYTES {
        limitations.push("HPACK table advertisement exceeds local reconstruction limit".into());
    }
    if updates > 1 {
        limitations.push("HPACK settings changes observed; cross-direction acknowledgement timing is not validated".into());
    }
    limit.min(MAX_HEADER_BYTES)
}

fn decode_direction(
    request: bool,
    frames: &[Frame<'_>],
    limit: usize,
    transactions: &mut BTreeMap<u32, MultiplexedTransaction>,
    report: &mut MultiplexedConversation,
) {
    let mut decoder = HeadersDecoder::new(limit);
    let mut pending: Option<HeaderBlock> = None;
    if frames
        .first()
        .is_some_and(|frame| frame.kind != 4 || frame.flags & 1 != 0)
    {
        report
            .limitations
            .push("HTTP/2 initial SETTINGS frame is missing".into());
        return;
    }
    for frame in frames {
        if pending.is_some()
            && (frame.kind != 9
                || pending
                    .as_ref()
                    .is_some_and(|block| block.promised_by.unwrap_or(block.id) != frame.stream_id))
        {
            report.limitations.push(
                "HTTP/2 header continuation was interrupted; direction decoding stopped".into(),
            );
            break;
        }
        if let Err(error) = process_frame(
            request,
            frame,
            &mut pending,
            &mut decoder,
            transactions,
            report,
        ) {
            report.limitations.push(error);
            break;
        }
    }
    if pending.is_some() {
        report
            .limitations
            .push("Incomplete HTTP/2 header continuation".into());
    }
}

fn process_frame(
    request: bool,
    frame: &Frame<'_>,
    pending: &mut Option<HeaderBlock>,
    decoder: &mut HeadersDecoder,
    transactions: &mut BTreeMap<u32, MultiplexedTransaction>,
    report: &mut MultiplexedConversation,
) -> Result<(), String> {
    match frame.kind {
        0 => {
            if frame.stream_id == 0 {
                return Err("HTTP/2 DATA on stream zero".into());
            }
            if request && frame.stream_id % 2 == 0 {
                return Err("Client DATA uses a server-initiated stream".into());
            }
            let (payload, offset) = unpad(frame)?;
            let transaction = transaction(transactions, frame.stream_id)?;
            let reset = transaction.reset_code.is_some();
            let message = if request {
                &mut transaction.request
            } else {
                &mut transaction.response
            };
            let message = message.get_or_insert_with(MultiplexedMessage::default);
            if reset {
                message.diagnostics.push("DATA after RST_STREAM".into());
            }
            if message.headers.is_empty() || message.end_stream || !message.trailers.is_empty() {
                message
                    .diagnostics
                    .push("DATA before headers or after message end".into());
            }
            if !payload.is_empty() {
                message.body.push(ByteSpan {
                    direction: frame.direction,
                    start: offset,
                    end: offset + payload.len(),
                });
            }
            add_packets(message, &frame.packets);
            message.end_stream |= frame.flags & 1 != 0;
        }
        1 | 5 => {
            if frame.stream_id == 0 {
                return Err("HTTP/2 HEADERS/PUSH_PROMISE on stream zero".into());
            }
            if request && frame.stream_id % 2 == 0 {
                return Err("Client HEADERS uses an even stream ID".into());
            }
            let (mut payload, _) = unpad(frame)?;
            let mut id = frame.stream_id;
            let mut promised_by = None;
            if frame.kind == 5 {
                if request || frame.flags & 1 != 0 {
                    return Err("Invalid client PUSH_PROMISE".into());
                }
                let number: [u8; 4] = payload
                    .get(..4)
                    .ok_or("Truncated PUSH_PROMISE")?
                    .try_into()
                    .unwrap();
                id = u32::from_be_bytes(number) & 0x7fff_ffff;
                if id == 0 || id % 2 != 0 {
                    return Err("Invalid promised stream ID".into());
                }
                promised_by = Some(frame.stream_id);
                payload = &payload[4..];
            } else if frame.flags & 0x20 != 0 {
                payload = payload.get(5..).ok_or("Truncated HTTP/2 priority fields")?;
            }
            if payload.len() > MAX_HEADER_BYTES {
                return Err("HTTP/2 header block limit exceeded".into());
            }
            *pending = Some(HeaderBlock {
                id,
                promised_by,
                bytes: payload.to_vec(),
                packets: frame.packets.clone(),
                end_stream: frame.kind == 5 || frame.flags & 1 != 0,
            });
            if frame.flags & 4 != 0 {
                apply_headers(request, pending.take().unwrap(), decoder, transactions)?;
            }
        }
        9 => {
            let block = pending.as_mut().ok_or("Unexpected HTTP/2 CONTINUATION")?;
            if block.bytes.len().saturating_add(frame.payload.len()) > MAX_HEADER_BYTES {
                return Err("HTTP/2 header block limit exceeded".into());
            }
            block.bytes.extend_from_slice(frame.payload);
            block.packets.extend_from_slice(&frame.packets);
            if frame.flags & 4 != 0 {
                apply_headers(request, pending.take().unwrap(), decoder, transactions)?;
            }
        }
        3 => {
            if frame.stream_id == 0 || frame.payload.len() != 4 {
                return Err("Invalid RST_STREAM frame".into());
            }
            transaction(transactions, frame.stream_id)?.reset_code =
                Some(u32::from_be_bytes(frame.payload.try_into().unwrap()) as u64);
        }
        4 => {
            if frame.stream_id != 0
                || frame.payload.len() % 6 != 0
                || frame.flags & 1 != 0 && !frame.payload.is_empty()
            {
                return Err("Invalid SETTINGS frame".into());
            }
        }
        6 => {
            if frame.stream_id != 0 || frame.payload.len() != 8 {
                return Err("Invalid PING frame".into());
            }
        }
        7 => {
            if frame.stream_id != 0 || frame.payload.len() < 8 {
                return Err("Invalid GOAWAY frame".into());
            }
            report.goaway_stream = Some(
                (u32::from_be_bytes(frame.payload[..4].try_into().unwrap()) & 0x7fff_ffff) as u64,
            );
        }
        8 => {
            if frame.payload.len() != 4
                || u32::from_be_bytes(frame.payload.try_into().unwrap()) & 0x7fff_ffff == 0
            {
                return Err("Invalid WINDOW_UPDATE frame".into());
            }
        }
        2 => {
            if frame.stream_id == 0 || frame.payload.len() != 5 {
                return Err("Invalid PRIORITY frame".into());
            }
        }
        _ => (),
    }
    Ok(())
}

fn transaction(
    transactions: &mut BTreeMap<u32, MultiplexedTransaction>,
    id: u32,
) -> Result<&mut MultiplexedTransaction, String> {
    if transactions.len() >= MAX_TRANSACTIONS && !transactions.contains_key(&id) {
        return Err("HTTP/2 transaction retention limit reached".into());
    }
    Ok(transactions
        .entry(id)
        .or_insert_with(|| MultiplexedTransaction::new(id.into())))
}

fn apply_headers(
    request: bool,
    block: HeaderBlock,
    decoder: &mut HeadersDecoder,
    transactions: &mut BTreeMap<u32, MultiplexedTransaction>,
) -> Result<(), String> {
    let headers = decoder.decode(&block.bytes)?;
    let transaction = transaction(transactions, block.id)?;
    let is_request = request || block.promised_by.is_some();
    if let Some(parent) = block.promised_by {
        transaction.promised_by = Some(parent.into());
    }
    let slot = if is_request {
        &mut transaction.request
    } else {
        &mut transaction.response
    };
    let message = slot.get_or_insert_with(MultiplexedMessage::default);
    let trailers = !message.headers.is_empty();
    if let Err(error) = validate(&headers, is_request, trailers) {
        message.diagnostics.push(error);
    }
    if message.end_stream {
        message.diagnostics.push("HEADERS after END_STREAM".into());
    }
    if trailers {
        if !block.end_stream {
            message
                .diagnostics
                .push("Trailers without END_STREAM".into());
        }
        message.trailers.extend(headers);
    } else {
        message.headers = headers;
    }
    add_packets(message, &block.packets);
    message.end_stream |= block.end_stream;
    if !is_request
        && message
            .header(":status")
            .is_some_and(|value| value.starts_with(b"1"))
    {
        let mut interim = slot.take().unwrap();
        if interim.end_stream {
            interim
                .diagnostics
                .push("Informational response sets END_STREAM".into());
        }
        interim.state = if interim.diagnostics.is_empty() {
            MessageState::Complete
        } else {
            MessageState::Ambiguous
        };
        if transaction.interim_responses.len() == 16 {
            return Err("HTTP/2 informational-response limit reached".into());
        }
        transaction.interim_responses.push(interim);
    }
    Ok(())
}

fn add_packets(message: &mut MultiplexedMessage, packets: &[u64]) {
    message.packet_numbers.extend_from_slice(packets);
    message.packet_numbers.sort_unstable();
    message.packet_numbers.dedup();
}

fn finish_message(
    message: Option<&mut MultiplexedMessage>,
    reset: Option<u64>,
    gaps: bool,
    no_body: bool,
) {
    let Some(message) = message else {
        return;
    };
    if !message.diagnostics.is_empty() {
        message.state = MessageState::Ambiguous;
    } else if message.end_stream && reset.is_none() && !gaps && !message.headers.is_empty() {
        message.state = MessageState::Complete;
    }
    if let Some(declared) = message.header("content-length") {
        let length = std::str::from_utf8(declared)
            .ok()
            .and_then(|value| value.parse::<usize>().ok());
        if length.is_none()
            || !no_body && message.end_stream && length != Some(message.body_bytes())
        {
            message.state = MessageState::Ambiguous;
            message
                .diagnostics
                .push("Content-Length does not match DATA bytes".into());
        }
    }
    if no_body && message.body_bytes() != 0 {
        message.state = MessageState::Ambiguous;
        message
            .diagnostics
            .push("DATA body on a bodyless response".into());
    }
}
