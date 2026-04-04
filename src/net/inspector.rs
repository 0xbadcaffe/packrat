//! Payload inspector — magic byte detection, XOR analysis, anomaly flagging.
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
    pub entropy:   f64,
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
