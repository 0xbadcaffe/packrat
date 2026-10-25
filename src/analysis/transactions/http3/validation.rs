use super::*;

pub(super) fn validate_event(event: &Http3Event) -> Result<(), String> {
    let kind = event.stream_id % 4;
    if event.stream_id > MAX_OFFSET
        || kind == 1
        || kind == 2 && event.sender != Http3Sender::Client
        || kind == 3 && event.sender != Http3Sender::Server
    {
        return Err("Invalid HTTP/3 stream type or unidirectional sender".into());
    }
    match &event.event {
        Http3EventKind::PushStart {
            wire_length,
            push_id,
        } => {
            if kind != 3
                || !matches!(wire_length, 2..=6 | 8..=10 | 12 | 16)
                || *push_id > MAX_OFFSET
            {
                return Err("Invalid HTTP/3 push stream prefix or sender".into());
            }
        }
        Http3EventKind::PushPromise {
            push_id, headers, ..
        } => {
            if kind != 0 || event.sender != Http3Sender::Server || *push_id > MAX_OFFSET {
                return Err("PUSH_PROMISE must originate on a server request direction".into());
            }
            validate_headers(headers)?;
        }
        Http3EventKind::ControlStart { wire_length } => {
            if kind < 2 || !matches!(wire_length, 1 | 2 | 4 | 8) {
                return Err("Invalid HTTP/3 control stream prefix".into());
            }
        }
        Http3EventKind::Settings { entries, .. } => {
            if kind < 2
                || entries.len() > 128
                || entries
                    .iter()
                    .any(|entry| entry.identifier > MAX_OFFSET || entry.value > MAX_OFFSET)
            {
                return Err("Invalid HTTP/3 SETTINGS metadata or field limit".into());
            }
        }
        Http3EventKind::Goaway { identifier, .. } => validate_control_id(kind, *identifier)?,
        Http3EventKind::MaxPushId { push_id, .. } | Http3EventKind::CancelPush { push_id, .. } => {
            validate_control_id(kind, *push_id)?
        }
        Http3EventKind::Headers { headers, .. } => validate_headers(headers)?,
        Http3EventKind::Data {
            wire_length, data, ..
        } => {
            if data.len() > 512 * 1024
                || !wire_length
                    .checked_sub(data.len() as u64)
                    .is_some_and(|header| matches!(header, 2..=6 | 8..=10 | 12 | 16))
            {
                return Err("HTTP/3 DATA size or framing metadata is invalid".into());
            }
        }
        Http3EventKind::Extension { frame_type, .. } => {
            if *frame_type > MAX_OFFSET
                || matches!(frame_type, 0 | 1 | 2 | 3 | 4 | 6 | 7 | 8 | 9 | 13)
                || (*frame_type == 5 && event.sender == Http3Sender::Client)
            {
                return Err(
                    "HTTP/3 known or control frame cannot masquerade as an extension".into(),
                );
            }
        }
        Http3EventKind::Finished { final_size } | Http3EventKind::Reset { final_size, .. } => {
            if *final_size > MAX_OFFSET {
                return Err("Invalid QUIC stream final size".into());
            }
            if let Http3EventKind::Reset { error_code, .. } = &event.event {
                if *error_code > MAX_OFFSET {
                    return Err("Invalid QUIC reset code".into());
                }
            }
        }
    }
    if let Some((offset, length)) = event.event.range() {
        let minimum = if matches!(event.event, Http3EventKind::ControlStart { .. }) {
            1
        } else {
            2
        };
        if !(minimum..=1_048_576).contains(&length)
            || offset
                .checked_add(length)
                .is_none_or(|end| end > MAX_OFFSET)
        {
            return Err("Invalid HTTP/3 plaintext frame range".into());
        }
    }
    Ok(())
}

fn validate_control_id(kind: u64, value: u64) -> Result<(), String> {
    if kind < 2 || value > MAX_OFFSET {
        return Err("Invalid HTTP/3 control frame stream or identifier".into());
    }
    Ok(())
}

pub(super) fn validate_headers(headers: &[super::super::HttpHeader]) -> Result<(), String> {
    if headers.len() > MAX_HEADERS
        || headers
            .iter()
            .map(|header| {
                header
                    .name
                    .len()
                    .saturating_add(header.value.len())
                    .saturating_add(32)
            })
            .sum::<usize>()
            > MAX_HEADER_BYTES
    {
        return Err("HTTP/3 decoded header limit exceeded".into());
    }
    Ok(())
}
