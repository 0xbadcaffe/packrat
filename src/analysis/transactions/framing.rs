use super::*;

#[derive(Debug)]
pub(super) struct Body {
    pub end: usize,
    pub spans: Vec<std::ops::Range<usize>>,
    pub trailers: Vec<HttpHeader>,
    pub state: MessageState,
    pub diagnostic: Option<String>,
    pub eof_delimited: bool,
}

impl Body {
    pub fn complete(end: usize) -> Self {
        Self {
            end,
            spans: Vec::new(),
            trailers: Vec::new(),
            state: MessageState::Complete,
            diagnostic: None,
            eof_delimited: false,
        }
    }
    fn problem(end: usize, state: MessageState, reason: &str) -> Self {
        Self {
            state,
            diagnostic: Some(reason.into()),
            ..Self::complete(end)
        }
    }
}

pub(super) fn frame_body(
    data: &[u8],
    start: usize,
    headers: &[httparse::Header<'_>],
    no_body: bool,
    request: bool,
    clean_eof: bool,
) -> Body {
    if no_body {
        return Body::complete(start);
    }
    let lengths: Vec<_> = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
        .flat_map(|header| header.value.split(|byte| *byte == b','))
        .collect();
    let encodings: Vec<_> = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("transfer-encoding"))
        .flat_map(|header| header.value.split(|byte| *byte == b','))
        .map(trim)
        .collect();
    if !lengths.is_empty() && !encodings.is_empty() {
        return Body::problem(
            start,
            MessageState::Ambiguous,
            "Both Transfer-Encoding and Content-Length are present",
        );
    }
    if !encodings.is_empty() {
        if encodings.len() == 1
            && encodings
                .last()
                .is_some_and(|value| value.eq_ignore_ascii_case(b"chunked"))
            && encodings
                .iter()
                .filter(|value| value.eq_ignore_ascii_case(b"chunked"))
                .count()
                == 1
            && encodings.iter().all(|value| !value.is_empty())
        {
            return chunked(data, start);
        }
        return Body::problem(
            start,
            MessageState::Unsupported,
            "Unsupported or ambiguous transfer coding",
        );
    }
    if !lengths.is_empty() {
        let mut declared = None;
        for value in lengths {
            let Some(length) = decimal(trim(value)) else {
                return Body::problem(start, MessageState::Ambiguous, "Invalid Content-Length");
            };
            if declared.is_some_and(|old| old != length) {
                return Body::problem(
                    start,
                    MessageState::Ambiguous,
                    "Conflicting Content-Length values",
                );
            }
            declared = Some(length);
        }
        let Some(end) = declared.and_then(|length| start.checked_add(length)) else {
            return Body::problem(
                start,
                MessageState::Unsupported,
                "Declared body length exceeds addressable range",
            );
        };
        let mut body = Body::complete(end.min(data.len()));
        if body.end > start {
            body.spans.push(start..body.end);
        }
        if end > data.len() {
            body.state = MessageState::Incomplete;
            body.diagnostic = Some("Content-Length body is incomplete".into());
        }
        return body;
    }
    if request {
        return Body::complete(start);
    }
    let mut body = Body::complete(data.len());
    body.eof_delimited = true;
    if data.len() > start {
        body.spans.push(start..data.len());
    }
    if !clean_eof {
        body.state = MessageState::Incomplete;
        body.diagnostic =
            Some("Close-delimited response requires a clean FIN and gap-free capture".into());
    }
    body
}

fn decimal(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0usize, |value, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(usize::from(byte - b'0'))
    })
}

fn trim(bytes: &[u8]) -> &[u8] {
    let first = bytes
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(bytes.len());
    let last = bytes
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map_or(first, |index| index + 1);
    &bytes[first..last]
}

fn chunked(data: &[u8], start: usize) -> Body {
    let mut body = Body::complete(start);
    for _ in 0..MAX_CHUNKS {
        let line = &data[body.end..data.len().min(body.end.saturating_add(4096))];
        if line.first().is_some_and(|byte| !byte.is_ascii_hexdigit()) {
            body.state = MessageState::Ambiguous;
            body.diagnostic = Some("Chunk-size line has no hexadecimal size".into());
            return body;
        }
        let (prefix, size) = match httparse::parse_chunk_size(line) {
            Ok(httparse::Status::Complete(value)) => value,
            Ok(httparse::Status::Partial) => {
                body.state = if line.len() == 4096 {
                    MessageState::Unsupported
                } else {
                    MessageState::Incomplete
                };
                body.diagnostic = Some("Chunk-size line incomplete or over limit".into());
                return body;
            }
            Err(_) => {
                body.state = MessageState::Ambiguous;
                body.diagnostic = Some("Invalid chunk-size line".into());
                return body;
            }
        };
        body.end += prefix;
        if size == 0 {
            return trailers(data, body);
        }
        let Some(end) = usize::try_from(size)
            .ok()
            .and_then(|size| body.end.checked_add(size))
        else {
            body.state = MessageState::Unsupported;
            body.diagnostic = Some("Chunk length exceeds addressable range".into());
            return body;
        };
        let retained_end = end.min(data.len());
        if retained_end > body.end {
            body.spans.push(body.end..retained_end);
        }
        body.end = retained_end;
        if end > data.len() || data.len().saturating_sub(end) < 2 {
            body.state = MessageState::Incomplete;
            body.diagnostic = Some("Chunk data or terminator is incomplete".into());
            return body;
        }
        if data.get(end..end + 2) != Some(b"\r\n") {
            body.state = MessageState::Ambiguous;
            body.diagnostic = Some("Chunk data has no CRLF terminator".into());
            return body;
        }
        body.end = end + 2;
    }
    body.state = MessageState::Unsupported;
    body.diagnostic = Some("Chunk count exceeds reconstruction limit".into());
    body
}

fn trailers(data: &[u8], mut body: Body) -> Body {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let bytes = &data[body.end..data.len().min(body.end.saturating_add(MAX_HEADER_BYTES))];
    match httparse::parse_headers(bytes, &mut headers) {
        Ok(httparse::Status::Complete((length, headers))) => {
            body.end += length;
            if bytes[..length]
                .iter()
                .enumerate()
                .any(|(index, byte)| *byte == b'\n' && (index == 0 || bytes[index - 1] != b'\r'))
                || headers.iter().any(|header| {
                    header.name.eq_ignore_ascii_case("content-length")
                        || header.name.eq_ignore_ascii_case("transfer-encoding")
                })
            {
                body.state = MessageState::Ambiguous;
                body.diagnostic =
                    Some("Non-CRLF trailer or trailer changes message framing".into());
            }
            body.trailers = headers
                .iter()
                .map(|header| HttpHeader {
                    name: header.name.into(),
                    value: header.value.to_vec(),
                })
                .collect();
        }
        Ok(httparse::Status::Partial) => {
            body.state = if bytes.len() == MAX_HEADER_BYTES {
                MessageState::Unsupported
            } else {
                MessageState::Incomplete
            };
            body.diagnostic = Some("Chunk trailers incomplete or over limit".into());
        }
        Err(_) => {
            body.state = MessageState::Ambiguous;
            body.diagnostic = Some("Invalid chunk trailers".into());
        }
    }
    body
}
