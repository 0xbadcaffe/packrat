//! TLS ClientHello parsing, JA4, ECH awareness, and QUIC invariant metadata.

use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct ClientHelloProfile {
    pub legacy_version: u16,
    pub negotiated_version: u16,
    pub client_random: String,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub ech_offered: bool,
    pub ja4: String,
}

pub fn parse_client_hello(raw: &[u8], transport: char) -> Option<ClientHelloProfile> {
    let record = find_handshake(raw, 1)?;
    if record.len() < 35 { return None; }
    let legacy_version = u16::from_be_bytes([record[0], record[1]]);
    let client_random = hex(&record[2..34]);
    let session_len = record[34] as usize;
    let mut pos = 35 + session_len;
    let cipher_len = read_u16(record, pos)? as usize;
    pos += 2;
    if pos + cipher_len > record.len() || cipher_len % 2 != 0 { return None; }
    let ciphers = record[pos..pos + cipher_len].chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .filter(|value| !is_grease(*value))
        .collect::<Vec<_>>();
    pos += cipher_len;
    let compression_len = *record.get(pos)? as usize;
    pos += 1 + compression_len;
    let extensions_len = read_u16(record, pos)? as usize;
    pos += 2;
    let end = pos.checked_add(extensions_len)?.min(record.len());

    let mut extensions = Vec::new();
    let mut signature_algorithms = Vec::new();
    let mut versions = Vec::new();
    let mut sni = None;
    let mut alpn = None;
    let mut ech_offered = false;
    while pos + 4 <= end {
        let kind = read_u16(record, pos)?;
        let len = read_u16(record, pos + 2)? as usize;
        pos += 4;
        if pos + len > end { break; }
        let body = &record[pos..pos + len];
        if !is_grease(kind) { extensions.push(kind); }
        match kind {
            0x0000 => sni = parse_sni(body),
            0x0010 => alpn = parse_alpn(body),
            0x000d => signature_algorithms = parse_u16_list(body, true),
            0x002b => versions = parse_u16_list(body, false),
            0xfe0d => ech_offered = true,
            _ => {}
        }
        pos += len;
    }
    let negotiated_version = versions.into_iter()
        .filter(|value| !is_grease(*value)).max().unwrap_or(legacy_version);
    let ja4 = compute_ja4(
        transport,
        negotiated_version,
        sni.is_some(),
        alpn.as_deref(),
        &ciphers,
        &extensions,
        &signature_algorithms,
    );
    Some(ClientHelloProfile {
        legacy_version,
        negotiated_version,
        client_random,
        sni,
        alpn,
        ciphers,
        extensions,
        signature_algorithms,
        ech_offered,
        ja4,
    })
}

pub fn parse_server_hello(raw: &[u8]) -> Option<(u16, u16)> {
    let record = find_handshake(raw, 2)?;
    if record.len() < 38 { return None; }
    let version = u16::from_be_bytes([record[0], record[1]]);
    let session_len = record[34] as usize;
    let cipher_pos = 35 + session_len;
    Some((version, read_u16(record, cipher_pos)?))
}

fn find_handshake(raw: &[u8], handshake_type: u8) -> Option<&[u8]> {
    let start = raw.windows(6).position(|window| {
        window[0] == 0x16 && window[1] == 0x03 && window[5] == handshake_type
    })?;
    let record_len = read_u16(raw, start + 3)? as usize;
    let handshake = start + 5;
    let handshake_len = ((raw.get(handshake + 1).copied()? as usize) << 16)
        | ((raw.get(handshake + 2).copied()? as usize) << 8)
        | raw.get(handshake + 3).copied()? as usize;
    let body = handshake + 4;
    let available_end = (start + 5 + record_len).min(raw.len());
    let end = body.checked_add(handshake_len)?.min(available_end);
    (body <= end).then_some(&raw[body..end])
}

fn parse_sni(body: &[u8]) -> Option<String> {
    let list_len = read_u16(body, 0)? as usize;
    if list_len + 2 > body.len() || *body.get(2)? != 0 { return None; }
    let name_len = read_u16(body, 3)? as usize;
    std::str::from_utf8(body.get(5..5 + name_len)?).ok().map(str::to_string)
}

fn parse_alpn(body: &[u8]) -> Option<String> {
    let list_len = read_u16(body, 0)? as usize;
    if list_len + 2 > body.len() { return None; }
    let len = *body.get(2)? as usize;
    std::str::from_utf8(body.get(3..3 + len)?).ok().map(str::to_string)
}

fn parse_u16_list(body: &[u8], two_byte_length: bool) -> Vec<u16> {
    let (start, length) = if two_byte_length {
        let Some(length) = read_u16(body, 0) else { return Vec::new(); };
        (2, length as usize)
    } else {
        let Some(length) = body.first() else { return Vec::new(); };
        (1, *length as usize)
    };
    let end = (start + length).min(body.len());
    body[start..end].chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect()
}

fn compute_ja4(
    transport: char,
    version: u16,
    has_sni: bool,
    alpn: Option<&str>,
    ciphers: &[u16],
    extensions: &[u16],
    signature_algorithms: &[u16],
) -> String {
    let version = match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    };
    let alpn = alpn.map(|value| {
        let first = value.chars().next().unwrap_or('0');
        let last = value.chars().last().unwrap_or('0');
        format!("{first}{last}")
    }).unwrap_or_else(|| "00".into());
    let a = format!(
        "{transport}{version}{}{:02}{:02}{alpn}",
        if has_sni { 'd' } else { 'i' },
        ciphers.len().min(99),
        extensions.len().min(99),
    );
    let mut sorted_ciphers = ciphers.to_vec();
    sorted_ciphers.sort_unstable();
    let cipher_text = sorted_ciphers.iter()
        .map(|value| format!("{value:04x}")).collect::<Vec<_>>().join(",");
    let mut sorted_extensions = extensions.iter().copied()
        .filter(|value| !matches!(value, 0x0000 | 0x0010)).collect::<Vec<_>>();
    sorted_extensions.sort_unstable();
    let extension_text = sorted_extensions.iter()
        .map(|value| format!("{value:04x}")).collect::<Vec<_>>().join(",");
    let signatures = signature_algorithms.iter()
        .map(|value| format!("{value:04x}")).collect::<Vec<_>>().join(",");
    format!("{a}_{}_{}", sha12(&cipher_text), sha12(&format!("{extension_text}_{signatures}")))
}

fn sha12(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))[..12].to_string()
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*bytes.get(offset)?, *bytes.get(offset + 1)?]))
}

fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicHeader {
    pub long_header: bool,
    pub fixed_bit: bool,
    pub version: Option<u32>,
    pub packet_type: &'static str,
    pub destination_id: String,
    pub source_id: String,
}

pub fn parse_quic_header(raw: &[u8]) -> Option<QuicHeader> {
    let start = find_quic_start(raw)?;
    let first = *raw.get(start)?;
    let long_header = first & 0x80 != 0;
    let fixed_bit = first & 0x40 != 0;
    if !long_header {
        return Some(QuicHeader {
            long_header,
            fixed_bit,
            version: None,
            packet_type: "1-RTT",
            destination_id: String::new(),
            source_id: String::new(),
        });
    }
    let version = u32::from_be_bytes([
        *raw.get(start + 1)?, *raw.get(start + 2)?, *raw.get(start + 3)?, *raw.get(start + 4)?,
    ]);
    let destination_len = *raw.get(start + 5)? as usize;
    if destination_len > 20 { return None; }
    let destination_start = start + 6;
    let destination_end = destination_start + destination_len;
    let source_len = *raw.get(destination_end)? as usize;
    if source_len > 20 { return None; }
    let source_start = destination_end + 1;
    let source_end = source_start + source_len;
    let packet_type = if version == 0 {
        "Version Negotiation"
    } else {
        match (first & 0x30) >> 4 {
            0 => "Initial",
            1 => "0-RTT",
            2 => "Handshake",
            _ => "Retry",
        }
    };
    Some(QuicHeader {
        long_header,
        fixed_bit,
        version: Some(version),
        packet_type,
        destination_id: hex(raw.get(destination_start..destination_end)?),
        source_id: hex(raw.get(source_start..source_end)?),
    })
}

fn find_quic_start(raw: &[u8]) -> Option<usize> {
    if raw.len() >= 14 {
        let mut network = 14;
        let mut ether_type = u16::from_be_bytes([raw[12], raw[13]]);
        while matches!(ether_type, 0x8100 | 0x88a8) && raw.len() >= network + 4 {
            ether_type = u16::from_be_bytes([raw[network + 2], raw[network + 3]]);
            network += 4;
        }
        let udp = match ether_type {
            0x0800 if raw.len() > network => {
                let ihl = ((raw[network] & 0x0f) as usize) * 4;
                (raw.get(network + 9) == Some(&17)).then_some(network + ihl)
            }
            0x86dd if raw.len() >= network + 40 => {
                (raw.get(network + 6) == Some(&17)).then_some(network + 40)
            }
            _ => None,
        };
        if let Some(start) = udp.and_then(|udp| udp.checked_add(8)) {
            if raw.get(start).is_some_and(|first| first & 0x40 != 0) {
                return Some(start);
            }
        }
    }
    (28..raw.len().saturating_sub(6)).find(|index| raw[*index] & 0xc0 == 0xc0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quic_v1_initial_invariant_header() {
        let mut packet = vec![0_u8; 42];
        packet.extend_from_slice(&[0xc0, 0, 0, 0, 1, 8]);
        packet.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        packet.push(4);
        packet.extend_from_slice(&[9, 10, 11, 12]);
        let header = parse_quic_header(&packet).unwrap();
        assert_eq!(header.version, Some(1));
        assert_eq!(header.packet_type, "Initial");
        assert_eq!(header.destination_id, "0102030405060708");
    }
}
