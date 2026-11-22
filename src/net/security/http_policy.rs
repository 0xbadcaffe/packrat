use super::*;

pub(super) const MAX_HTTP_HEADER_BYTES: usize = 16_384;
pub(super) const MAX_HTTP_HEADERS: usize = 48;

pub(super) fn response_status(payload: &[u8]) -> Option<u16> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    let bounded = &payload[..payload.len().min(MAX_HTTP_HEADER_BYTES)];
    if !response.parse(bounded).ok()?.is_complete() {
        return None;
    }
    response.code.filter(|code| (100..=599).contains(code))
}

pub(super) fn basic_authorization_header(payload: &[u8]) -> Option<&'static str> {
    let header = &payload[..payload.len().min(MAX_HTTP_HEADER_BYTES)];
    let end = header.windows(4).position(|window| window == b"\r\n\r\n")?;
    let mut lines = header[..end + 2].split_inclusive(|&byte| byte == b'\n');
    let mut request = lines.next()?.strip_suffix(b"\r\n")?.split(|&byte| byte == b' ');
    let method = request.next()?;
    let target = request.next()?;
    if !matches!(method, b"GET" | b"HEAD" | b"POST" | b"PUT" | b"PATCH" | b"DELETE" | b"OPTIONS" | b"CONNECT" | b"TRACE")
        || target.is_empty() || target.iter().any(|byte| !byte.is_ascii_graphic())
        || !matches!(request.next()?, b"HTTP/1.0" | b"HTTP/1.1") || request.next().is_some()
    {
        return None;
    }
    for line in lines {
        let line = line.strip_suffix(b"\r\n")?;
        let colon = line.iter().position(|&byte| byte == b':')?;
        let name = &line[..colon];
        let label = if name.eq_ignore_ascii_case(b"authorization") {
            "Authorization"
        } else if name.eq_ignore_ascii_case(b"proxy-authorization") {
            "Proxy-Authorization"
        } else {
            continue;
        };
        let value = std::str::from_utf8(&line[colon + 1..]).ok()?.trim_matches([' ', '\t']);
        if let Some((scheme, credentials)) = value.split_once(' ')
            && scheme.eq_ignore_ascii_case("basic")
            && valid_basic_token(credentials.trim_start_matches(' ').as_bytes())
        {
            return Some(label);
        }
    }
    None
}

fn valid_basic_token(token: &[u8]) -> bool {
    if token.is_empty() || token.len() % 4 != 0 {
        return false;
    }
    let padding = token.iter().rev().take_while(|&&byte| byte == b'=').count();
    if padding > 2 {
        return false;
    }
    // Check the user-pass separator without allocating or retaining decoded credentials.
    let (mut bits, mut shift, mut separator) = (0_u16, 0_u8, false);
    for &byte in &token[..token.len() - padding] {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return false,
        };
        bits = (bits << 6) | u16::from(value);
        shift += 6;
        if shift >= 8 {
            shift -= 8;
            let decoded = (bits >> shift) as u8;
            if decoded.is_ascii_control() {
                return false;
            }
            separator |= decoded == b':';
        }
    }
    separator && bits & ((1 << shift) - 1) == 0
}

pub(super) fn find_http_header_end(bytes: &[u8]) -> Option<usize> {
    if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
        return Some(index + 4);
    }
    bytes
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|index| index + 2)
}

pub(super) fn http_smuggling_reason(header: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(header);
    let mut lines = text.split('\n');
    let request_line = lines.next()?.trim_end_matches('\r');
    let method = request_line.split_whitespace().next()?;
    if !matches!(
        method,
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "CONNECT" | "TRACE"
    ) {
        return None;
    }

    let mut content_lengths = Vec::new();
    let mut transfer_codings = Vec::new();
    let mut malformed_framing_name = None;
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((raw_name, raw_value)) = line.split_once(':') else {
            continue;
        };
        let name = raw_name.trim().to_ascii_lowercase();
        if matches!(name.as_str(), "content-length" | "transfer-encoding")
            && raw_name != raw_name.trim()
        {
            malformed_framing_name = Some(name.clone());
        }
        if name == "content-length" {
            for value in raw_value.split(',') {
                content_lengths.push(value.trim().parse::<u64>().ok());
            }
        } else if name == "transfer-encoding" {
            transfer_codings.extend(
                raw_value
                    .split(',')
                    .map(|value| value.trim().to_ascii_lowercase()),
            );
        }
    }

    if let Some(name) = malformed_framing_name {
        return Some(format!("whitespace-obfuscated {name} header"));
    }
    if content_lengths.iter().any(Option::is_none) {
        return Some("invalid Content-Length value".into());
    }
    let distinct_lengths = content_lengths
        .iter()
        .flatten()
        .copied()
        .collect::<HashSet<_>>();
    if distinct_lengths.len() > 1 {
        return Some("conflicting Content-Length values".into());
    }
    if !content_lengths.is_empty() && !transfer_codings.is_empty() {
        return Some("both Transfer-Encoding and Content-Length are present".into());
    }
    if let Some(chunked_index) = transfer_codings
        .iter()
        .position(|coding| coding == "chunked")
    {
        if chunked_index + 1 != transfer_codings.len() {
            return Some("chunked transfer coding is not final".into());
        }
    }
    if header.windows(2).any(|window| window == b"\n\n")
        && !header.windows(4).any(|window| window == b"\r\n\r\n")
    {
        return Some("bare-LF request framing".into());
    }
    None
}
