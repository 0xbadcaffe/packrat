use super::*;

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
