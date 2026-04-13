//! TLS intelligence — SNI extraction, cipher suite tracking, JA3 fingerprinting.

use std::collections::HashMap;
use crate::net::packet::Packet;

// ─── TLS record types ─────────────────────────────────────────────────────────

const TLS_HANDSHAKE:     u8 = 0x16;
const TLS_CLIENT_HELLO:  u8 = 0x01;
const TLS_SERVER_HELLO:  u8 = 0x02;

// ─── TLS session ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct TlsSession {
    pub flow_id:         String,
    pub sni:             Option<String>,
    pub cipher_suite:    Option<u16>,
    pub tls_version:     Option<String>,
    pub ja3:             Option<String>,
    pub ja3s:            Option<String>,
    pub cert_cn:         Option<String>,
    pub cert_san:        Vec<String>,
    pub cert_issuer:     Option<String>,
    pub cert_not_after:  Option<String>,
    pub first_seen:      f64,
    pub alert_level:     Option<u8>,   // TLS alert level (1=warning, 2=fatal)
    pub alert_desc:      Option<u8>,   // TLS alert description
}

impl TlsSession {
    pub fn version_str(&self) -> &str {
        self.tls_version.as_deref().unwrap_or("unknown")
    }

    pub fn is_weak(&self) -> bool {
        match self.cipher_suite {
            Some(cs) => WEAK_CIPHERS.contains(&cs),
            None => false,
        }
    }
}

/// Known weak / deprecated cipher suites.
static WEAK_CIPHERS: &[u16] = &[
    0x0004, // TLS_RSA_WITH_RC4_128_MD5
    0x0005, // TLS_RSA_WITH_RC4_128_SHA
    0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
    0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
    0x0001, // TLS_RSA_WITH_NULL_MD5
    0x0002, // TLS_RSA_WITH_NULL_SHA
];

// ─── TLS tracker ──────────────────────────────────────────────────────────────

const MAX_SESSIONS: usize = 1000;

#[derive(Debug, Default)]
pub struct TlsTracker {
    sessions: HashMap<String, TlsSession>,
}

impl TlsTracker {
    pub fn ingest(&mut self, pkt: &Packet) {
        // Quick check: look for TLS record in packet bytes
        let bytes = &pkt.bytes;

        // Ethernet(14) + IP(20) + TCP(20) = 54 bytes minimum
        if bytes.len() < 60 { return; }

        let payload_start = 54; // approximate
        let payload = &bytes[payload_start..];

        if payload.is_empty() || payload[0] != TLS_HANDSHAKE { return; }
        if payload.len() < 6 { return; }

        let flow_id = make_flow_id(pkt);

        if payload.len() > 5 {
            let handshake_type = payload[5];
            match handshake_type {
                TLS_CLIENT_HELLO => {
                    let session = self.sessions.entry(flow_id.clone())
                        .or_insert_with(|| TlsSession {
                            flow_id: flow_id.clone(),
                            first_seen: pkt.timestamp,
                            ..Default::default()
                        });

                    // Extract TLS version from ClientHello (bytes 9-10 after start of payload)
                    if payload.len() > 11 {
                        let major = payload[9];
                        let minor = payload[10];
                        session.tls_version = Some(tls_version_str(major, minor));
                    }

                    // Extract SNI from extensions
                    if let Some(sni) = extract_sni(payload) {
                        session.sni = Some(sni);
                    }

                    // Simple JA3: version + cipher_suites + extensions (approximate)
                    session.ja3 = Some(compute_ja3_simple(payload));
                }
                TLS_SERVER_HELLO => {
                    let session = self.sessions.entry(flow_id.clone())
                        .or_insert_with(|| TlsSession {
                            flow_id: flow_id.clone(),
                            first_seen: pkt.timestamp,
                            ..Default::default()
                        });

                    if payload.len() > 11 {
                        let major = payload[9];
                        let minor = payload[10];
                        if session.tls_version.is_none() {
                            session.tls_version = Some(tls_version_str(major, minor));
                        }
                    }

                    // Extract selected cipher suite (bytes 11-12 in ServerHello)
                    if payload.len() > 13 {
                        let cs = u16::from_be_bytes([payload[11], payload[12]]);
                        session.cipher_suite = Some(cs);
                    }
                }
                _ => {}
            }
        }

        // Evict if over cap
        if self.sessions.len() > MAX_SESSIONS {
            if let Some(oldest) = self.sessions.iter()
                .min_by(|a, b| a.1.first_seen.partial_cmp(&b.1.first_seen).unwrap())
                .map(|(k, _)| k.clone())
            {
                self.sessions.remove(&oldest);
            }
        }
    }

    /// Directly insert a pre-built session (used for scenario/demo seeding).
    pub fn insert(&mut self, session: TlsSession) {
        if self.sessions.len() < MAX_SESSIONS {
            self.sessions.insert(session.flow_id.clone(), session);
        }
    }

    pub fn get(&self, flow_id: &str) -> Option<&TlsSession> { self.sessions.get(flow_id) }

    pub fn all(&self) -> Vec<&TlsSession> {
        let mut v: Vec<_> = self.sessions.values().collect();
        v.sort_by(|a, b| b.first_seen.partial_cmp(&a.first_seen).unwrap_or(std::cmp::Ordering::Equal));
        v
    }

    pub fn with_sni(&self) -> Vec<&TlsSession> {
        self.all().into_iter().filter(|s| s.sni.is_some()).collect()
    }

    pub fn weak_sessions(&self) -> Vec<&TlsSession> {
        self.all().into_iter().filter(|s| s.is_weak()).collect()
    }

    pub fn len(&self) -> usize { self.sessions.len() }
    pub fn is_empty(&self) -> bool { self.sessions.is_empty() }
    pub fn clear(&mut self) { self.sessions.clear(); }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn make_flow_id(pkt: &Packet) -> String {
    let sp = pkt.src_port.unwrap_or(0);
    let dp = pkt.dst_port.unwrap_or(0);
    let a = format!("{}:{}", pkt.src, sp);
    let b = format!("{}:{}", pkt.dst, dp);
    if a < b { format!("{a}-{b}") } else { format!("{b}-{a}") }
}

fn tls_version_str(major: u8, minor: u8) -> String {
    match (major, minor) {
        (3, 1) => "TLS 1.0".into(),
        (3, 2) => "TLS 1.1".into(),
        (3, 3) => "TLS 1.2".into(),
        (3, 4) => "TLS 1.3".into(),
        _      => format!("TLS {major}.{minor}"),
    }
}

fn cipher_suite_name(cs: u16) -> &'static str {
    match cs {
        0xC02B => "ECDHE-ECDSA-AES128-GCM-SHA256",
        0xC02F => "ECDHE-RSA-AES128-GCM-SHA256",
        0xC02C => "ECDHE-ECDSA-AES256-GCM-SHA384",
        0xC030 => "ECDHE-RSA-AES256-GCM-SHA384",
        0x1301 => "TLS_AES_128_GCM_SHA256 (TLS1.3)",
        0x1302 => "TLS_AES_256_GCM_SHA384 (TLS1.3)",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256 (TLS1.3)",
        0x0005 => "RC4-SHA (WEAK)",
        0x000A => "3DES-CBC-SHA (WEAK)",
        _      => "unknown",
    }
}

pub fn cipher_name(cs: u16) -> &'static str { cipher_suite_name(cs) }

/// Very rough SNI extraction — looks for extension type 0x0000 (server_name).
fn extract_sni(hello: &[u8]) -> Option<String> {
    // ClientHello structure (simplified):
    // [0] = 0x16 (handshake)
    // [1-2] = TLS version
    // [3-4] = record length
    // [5]   = 0x01 (client_hello type)
    // [6-8] = message length
    // [9-10] = client version
    // [11-42] = random (32 bytes)
    // [43]   = session_id length
    let sid_len = *hello.get(43)? as usize;
    let mut pos = 44 + sid_len;

    // Cipher suites length
    if pos + 2 > hello.len() { return None; }
    let cs_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // Compression methods
    if pos >= hello.len() { return None; }
    let comp_len = hello[pos] as usize;
    pos += 1 + comp_len;

    // Extensions
    if pos + 2 > hello.len() { return None; }
    let ext_total = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_total;
    while pos + 4 <= ext_end && pos + 4 <= hello.len() {
        let ext_type = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
        let ext_len  = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 && pos + ext_len <= hello.len() {
            // server_name extension
            // [0-1] = list length, [2] = name_type (0=host_name), [3-4] = name length
            if ext_len >= 5 {
                let name_len = u16::from_be_bytes([hello[pos + 3], hello[pos + 4]]) as usize;
                if pos + 5 + name_len <= hello.len() {
                    let name_bytes = &hello[pos + 5..pos + 5 + name_len];
                    return String::from_utf8(name_bytes.to_vec()).ok();
                }
            }
        }
        pos += ext_len;
    }
    None
}

fn compute_ja3_simple(hello: &[u8]) -> String {
    // JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
    // We produce a simplified hash of the byte sequence as a stand-in.
    let mut h: u64 = 14_695_981_039_346_656_037;
    for &b in hello {
        h ^= b as u64;
        h = h.wrapping_mul(1_099_511_628_211);
    }
    format!("{h:016x}")
}
