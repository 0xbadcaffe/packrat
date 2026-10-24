use super::{HttpHeader, MAX_HEADER_BYTES, MAX_HEADERS};

pub(super) struct HeadersDecoder(loona_hpack::Decoder<'static>);

impl HeadersDecoder {
    pub fn new(table_limit: usize) -> Self {
        let mut decoder = loona_hpack::Decoder::new();
        decoder.set_max_allowed_table_size(table_limit.min(MAX_HEADER_BYTES));
        decoder.set_max_table_size(table_limit.min(4096));
        Self(decoder)
    }

    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<HttpHeader>, String> {
        let mut headers = Vec::new();
        let mut size = 0usize;
        let mut exceeded = false;
        self.0
            .decode_with_cb(block, |name, value| {
                size = size
                    .saturating_add(name.len())
                    .saturating_add(value.len())
                    .saturating_add(32);
                if size > MAX_HEADER_BYTES || headers.len() == MAX_HEADERS {
                    exceeded = true;
                    return;
                }
                headers.push(HttpHeader {
                    name: String::from_utf8_lossy(&name).into_owned(),
                    value: value.into_owned(),
                });
            })
            .map_err(|error| format!("Invalid HPACK block: {error}"))?;
        if exceeded {
            return Err("Decoded HTTP/2 header limit exceeded".into());
        }
        Ok(headers)
    }
}

pub(super) fn validate(
    headers: &[HttpHeader],
    request: bool,
    trailers: bool,
) -> Result<(), String> {
    let mut regular = false;
    let mut pseudo = std::collections::HashSet::new();
    for header in headers {
        let name = header.name.as_bytes();
        if name.is_empty()
            || name
                .iter()
                .any(|byte| byte.is_ascii_uppercase() || !byte.is_ascii_graphic())
            || header
                .value
                .iter()
                .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
        {
            return Err("Invalid HTTP field name or value".into());
        }
        if header
            .value
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
            || header
                .value
                .last()
                .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            return Err("HTTP field value has leading or trailing whitespace".into());
        }
        if header.name.starts_with(':') {
            if trailers || regular || !pseudo.insert(header.name.as_str()) {
                return Err("Duplicate, misplaced, or trailer pseudo-header".into());
            }
            let allowed = if request {
                matches!(
                    header.name.as_str(),
                    ":method" | ":scheme" | ":path" | ":authority" | ":protocol"
                )
            } else {
                header.name == ":status"
            };
            if !allowed {
                return Err("Pseudo-header has the wrong message role".into());
            }
        } else {
            if !name
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte))
            {
                return Err("Invalid HTTP field name token".into());
            }
            regular = true;
        }
        if matches!(
            header.name.as_str(),
            "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
        ) || header.name == "te" && !header.value.eq_ignore_ascii_case(b"trailers")
        {
            return Err("Connection-specific field in multiplexed HTTP message".into());
        }
    }
    if trailers {
        return Ok(());
    }
    if request {
        let method = headers
            .iter()
            .find(|header| header.name == ":method")
            .map(|header| header.value.as_slice())
            .filter(|value| !value.is_empty())
            .ok_or("Missing :method")?;
        if method != b"CONNECT" && (!pseudo.contains(":scheme") || !pseudo.contains(":path")) {
            return Err("Missing request :scheme or :path".into());
        }
        if method == b"CONNECT" && !pseudo.contains(":authority") {
            return Err("CONNECT has no :authority".into());
        }
    } else {
        let value = headers
            .iter()
            .find(|header| header.name == ":status")
            .map(|header| header.value.as_slice())
            .ok_or("Missing :status")?;
        if value.len() != 3
            || !value.iter().all(u8::is_ascii_digit)
            || !(b'1'..=b'5').contains(&value[0])
            || value == b"101"
        {
            return Err("Invalid HTTP :status".into());
        }
    }
    Ok(())
}
