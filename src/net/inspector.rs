//! Payload inspector — magic byte detection, XOR analysis, anomaly flagging, credential extraction.
use crate::net::packet::Packet;

pub struct MagicMatch {
    pub name:   &'static str,
    pub offset: usize,
}

pub struct XorResult {
    pub key:   u8,
    pub score: f64,
}

pub struct Indicators {
    pub magic:     Vec<MagicMatch>,
    pub xor:       Option<XorResult>,
    pub anomalies: Vec<String>,
    #[allow(dead_code)]
    pub entropy:   f64,
}

pub struct CredentialHit {
    #[allow(dead_code)]
    pub proto:  String,
    pub kind:   &'static str,  // "HTTP-BasicAuth", "FTP-USER", "FTP-PASS", "SMTP-AUTH", "IMAP-LOGIN"
    pub value:  String,        // decoded credential
    pub pkt_no: u64,
}

const MAGIC_SIGS: &[(&str, &[u8])] = &[
    ("ELF",    &[0x7f, b'E', b'L', b'F']),
    ("PE/EXE", &[b'M', b'Z']),
    ("PNG",    &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]),
    ("JPEG",   &[0xff, 0xd8, 0xff]),
    ("ZIP",    &[b'P', b'K', 0x03, 0x04]),
    ("PDF",    &[b'%', b'P', b'D', b'F']),
    ("gzip",   &[0x1f, 0x8b]),
    ("LZ4",    &[0x04, 0x22, 0x4d, 0x18]),
    ("Zstd",   &[0xfd, b'2', b's', b't', b'd']),
    ("OGG",    &[b'O', b'g', b'g', b'S']),
    ("RIFF",   &[b'R', b'I', b'F', b'F']),
    ("bzip2",  &[b'B', b'Z', b'h']),
    ("SQLite", &[b'S', b'Q', b'L', b'i', b't', b'e']),
    ("7-Zip",  &[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]),
    ("SSH-key",&[b'S', b'S', b'H', b'-']),
    ("PEM",    &[b'-', b'-', b'-', b'-', b'-']),
];

const SCAN_OFFSETS: &[usize] = &[0, 14, 34, 42, 54, 66];

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for &b in data { counts[b as usize] += 1; }
    let n = data.len() as f64;
    -counts.iter().filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / n; p * p.log2() })
        .sum::<f64>()
}


pub fn detect_magic(payload: &[u8]) -> Vec<MagicMatch> {
    let mut found = Vec::new();
    for &off in SCAN_OFFSETS {
        if off >= payload.len() { break; }
        let slice = &payload[off..];
        for &(name, sig) in MAGIC_SIGS {
            if slice.starts_with(sig) {
                found.push(MagicMatch { name, offset: off });
            }
        }
    }
    found
}

pub fn detect_xor(payload: &[u8]) -> Option<XorResult> {
    if payload.len() < 16 { return None; }
    let sample = &payload[..payload.len().min(512)];
    let orig_printable = sample.iter().filter(|&&b| b >= 32 && b < 127).count() as f64 / sample.len() as f64;
    if orig_printable > 0.75 { return None; }
    let (best_key, best_score) = (1u8..=255).map(|k| {
        let printable = sample.iter().filter(|&&b| { let x = b ^ k; x >= 32 && x < 127 }).count();
        (k, printable as f64 / sample.len() as f64)
    }).max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())?;
    if best_score > 0.70 { Some(XorResult { key: best_key, score: best_score }) } else { None }
}

pub fn detect_anomalies(pkt: &Packet) -> Vec<String> {
    let mut anomalies = Vec::new();
    // HTTP content on non-standard port
    if pkt.bytes.windows(4).any(|w| w == b"HTTP" || w == b"GET " || w == b"POST") {
        let dp = pkt.dst_port.unwrap_or(0);
        let sp = pkt.src_port.unwrap_or(0);
        if !matches!(dp, 80 | 8080 | 443 | 8443 | 3000 | 8000 | 8888)
           && !matches!(sp, 80 | 8080 | 443 | 8443 | 3000 | 8000 | 8888) {
            anomalies.push(format!("HTTP content on non-standard port {}/{}", sp, dp));
        }
    }
    // SSH banner on non-standard port
    if pkt.bytes.windows(4).any(|w| w == b"SSH-") {
        let dp = pkt.dst_port.unwrap_or(0);
        let sp = pkt.src_port.unwrap_or(0);
        if !matches!(dp | sp, 22) {
            anomalies.push(format!("SSH banner on non-standard port {}/{}", sp, dp));
        }
    }
    // High entropy on cleartext protocol
    let entropy = shannon_entropy(&pkt.bytes);
    if entropy > 7.2 && matches!(pkt.protocol.as_str(), "HTTP" | "FTP" | "Telnet" | "SMTP") {
        anomalies.push(format!("High entropy ({:.2} bits/byte) in cleartext protocol — possible tunneling", entropy));
    }

    // TCP flag anomalies — look for flag byte at typical TCP header offset
    let flag_offsets = [47usize, 33, 13]; // try multiple offsets
    for &off in &flag_offsets {
        if pkt.bytes.len() > off {
            let flags = pkt.bytes[off];
            // XMAS scan: FIN+PSH+URG (0x29)
            if flags == 0x29 {
                anomalies.push("TCP XMAS scan (FIN+PSH+URG flags)".to_string());
                break;
            }
            // NULL scan: no flags (0x00)
            if flags == 0x00 && pkt.protocol == "TCP" {
                anomalies.push("TCP NULL scan (no flags set)".to_string());
                break;
            }
            // SYN+FIN: invalid combination
            if flags & 0x03 == 0x03 {
                anomalies.push("TCP SYN+FIN — invalid flag combination".to_string());
                break;
            }
            // FIN only (no ACK): FIN probe
            if flags == 0x01 {
                anomalies.push("TCP FIN-only probe (no ACK)".to_string());
                break;
            }
        }
    }

    anomalies
}

pub fn inspect(pkt: &Packet) -> Indicators {
    let entropy = shannon_entropy(&pkt.bytes);
    Indicators {
        magic: detect_magic(&pkt.bytes),
        xor: detect_xor(&pkt.bytes),
        anomalies: detect_anomalies(pkt),
        entropy,
    }
}

// ── Inline base64 decoder ─────────────────────────────────────────────────────

fn b64_decode(input: &str) -> Option<Vec<u8>> {
    let input = input.trim().replace(['\r', '\n', ' '], "");
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() { lookup[c as usize] = i as u8; }
    let mut out = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i + 3 < bytes.len() {
        let a = lookup.get(bytes[i] as usize).copied().unwrap_or(255);
        let b = lookup.get(bytes[i+1] as usize).copied().unwrap_or(255);
        let c = lookup.get(bytes[i+2] as usize).copied().unwrap_or(255);
        let d = lookup.get(bytes[i+3] as usize).copied().unwrap_or(255);
        if a == 255 || b == 255 { break; }
        out.push((a << 2) | (b >> 4));
        if bytes[i+2] != b'=' { out.push(((b & 0x0f) << 4) | (c >> 2)); }
        if bytes[i+3] != b'=' && c != 255 { out.push(((c & 0x03) << 6) | d); }
        i += 4;
    }
    Some(out)
}

// ── Credential extraction ─────────────────────────────────────────────────────

pub fn extract_credentials(pkt: &Packet) -> Vec<CredentialHit> {
    let mut hits = Vec::new();
    let text = match std::str::from_utf8(&pkt.bytes) {
        Ok(s) => s.to_string(),
        Err(_) => return hits,
    };

    // HTTP Basic Auth: "Authorization: Basic <b64>"
    if let Some(pos) = text.find("Authorization: Basic ") {
        let rest = &text[pos + 21..];
        let end = rest.find(|c: char| c == '\r' || c == '\n').unwrap_or(rest.len());
        let b64 = &rest[..end.min(rest.len())];
        if let Some(decoded) = b64_decode(b64.trim()) {
            if let Ok(s) = std::str::from_utf8(&decoded) {
                hits.push(CredentialHit {
                    proto: pkt.protocol.clone(),
                    kind: "HTTP-BasicAuth",
                    value: s.to_string(),
                    pkt_no: pkt.no,
                });
            }
        }
    }

    // FTP USER / PASS
    for line in text.lines() {
        let upper = line.trim_start().to_uppercase();
        if upper.starts_with("USER ") {
            hits.push(CredentialHit {
                proto: "FTP".into(),
                kind: "FTP-USER",
                value: line.trim().to_string(),
                pkt_no: pkt.no,
            });
        } else if upper.starts_with("PASS ") {
            hits.push(CredentialHit {
                proto: "FTP".into(),
                kind: "FTP-PASS",
                value: line.trim().to_string(),
                pkt_no: pkt.no,
            });
        }
    }

    // SMTP AUTH PLAIN / LOGIN (base64-encoded credentials)
    if text.contains("AUTH PLAIN") || text.contains("AUTH LOGIN") {
        // Look for base64 blobs on their own lines
        for line in text.lines() {
            let t = line.trim();
            if t.len() > 8 && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
                if let Some(decoded) = b64_decode(t) {
                    if let Ok(s) = std::str::from_utf8(&decoded) {
                        if s.contains('\0') || s.len() > 3 {
                            hits.push(CredentialHit {
                                proto: "SMTP".into(),
                                kind: "SMTP-AUTH",
                                value: s.replace('\0', ":"),
                                pkt_no: pkt.no,
                            });
                        }
                    }
                }
            }
        }
    }

    // IMAP LOGIN / POP3 USER+PASS (cleartext)
    for line in text.lines() {
        let t = line.trim();
        let u = t.to_uppercase();
        if u.contains("LOGIN ") && !u.starts_with('*') {
            hits.push(CredentialHit {
                proto: pkt.protocol.clone(),
                kind: "IMAP-LOGIN",
                value: t.to_string(),
                pkt_no: pkt.no,
            });
        }
    }

    hits
}

// ── DNS tunneling detection ───────────────────────────────────────────────────

#[allow(dead_code)]
pub fn detect_dns_tunneling(packets: &std::collections::VecDeque<Packet>) -> Vec<String> {
    use std::collections::HashMap;
    let mut apex_map: HashMap<String, (usize, f64, usize)> = HashMap::new(); // apex → (unique_subdomains, max_entropy, max_label_len)

    for pkt in packets {
        if pkt.protocol != "DNS" && pkt.protocol != "mDNS" { continue; }
        // Extract domain from info string (format: "Query 0xXXXX A domain.com")
        let parts: Vec<&str> = pkt.info.split_whitespace().collect();
        if let Some(domain) = parts.last() {
            if domain.contains('.') {
                let labels: Vec<&str> = domain.split('.').collect();
                if labels.len() >= 2 {
                    let apex = format!("{}.{}", labels[labels.len()-2], labels[labels.len()-1]);
                    let subdomain = if labels.len() > 2 { labels[..labels.len()-2].join(".") } else { String::new() };
                    let entry = apex_map.entry(apex).or_insert((0, 0.0, 0));
                    if !subdomain.is_empty() {
                        entry.0 += 1; // unique subdomain count (approximate)
                        let ent = shannon_entropy(subdomain.as_bytes());
                        if ent > entry.1 { entry.1 = ent; }
                        if subdomain.len() > entry.2 { entry.2 = subdomain.len(); }
                    }
                }
            }
        }
    }

    let mut findings = Vec::new();
    for (apex, (count, max_ent, max_len)) in &apex_map {
        if *count > 20 || *max_ent > 3.5 || *max_len > 30 {
            findings.push(format!(
                "DNS tunneling candidate: {} ({} unique subdomains, max entropy={:.2}, max label len={})",
                apex, count, max_ent, max_len
            ));
        }
    }
    findings
}
