//! TLS intelligence — SNI extraction, cipher suite tracking, JA3 fingerprinting.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use crate::analysis::helper_process::JsonLineHelper;
use crate::analysis::encrypted_insight::{parse_anchored_server_hello, parse_client_hello};
use crate::analysis::key_shelf::KeyShelf;
use crate::analysis::stream::{StreamKey, tcp_complete_segment_payload};
use crate::net::packet::Packet;

// ─── TLS record types ─────────────────────────────────────────────────────────

const TLS_HANDSHAKE:     u8 = 0x16;
const TLS_CLIENT_HELLO:  u8 = 0x01;
const TLS_SERVER_HELLO:  u8 = 0x02;
const TLS_APPLICATION_DATA: u8 = 0x17;

// ─── TLS session ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct DecryptedTlsRecord {
    pub packet_no: u64,
    pub content_type: String,
    pub plaintext: Vec<u8>,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct TlsSession {
    pub flow_id:         String,
    pub sni:             Option<String>,
    pub cipher_suite:    Option<u16>,
    pub tls_version:     Option<String>,
    pub offered_version: Option<String>,
    pub ja3:             Option<String>,
    pub ja3s:            Option<String>,
    pub ja4:             Option<String>,
    pub client_random:   Option<String>,
    pub alpn:            Option<String>,
    pub ech_offered:     bool,
    /// Matching key-log material is available. Payload decryption is only
    /// reported after a decoder successfully authenticates records.
    pub key_material:    bool,
    pub cert_cn:         Option<String>,
    pub cert_san:        Vec<String>,
    pub cert_issuer:     Option<String>,
    pub cert_not_after:  Option<String>,
    pub first_seen:      f64,
    pub alert_level:     Option<u8>,   // TLS alert level (1=warning, 2=fatal)
    pub alert_desc:      Option<u8>,   // TLS alert description
    pub decrypted_records: Vec<DecryptedTlsRecord>,
    pub(crate) packet_numbers: VecDeque<u64>,
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
const MAX_PACKET_LINKS: usize = 128;

#[derive(Debug)]
pub struct TlsTracker {
    sessions: HashMap<String, TlsSession>,
    pub key_shelf: KeyShelf,
    pub decrypt_helper_path: Option<PathBuf>,
    decrypt_helper: Option<JsonLineHelper>,
}

impl Default for TlsTracker {
    fn default() -> Self {
        Self { sessions: HashMap::new(), key_shelf: KeyShelf::default(), decrypt_helper_path: None, decrypt_helper: None }
    }
}

#[derive(Debug, serde::Serialize)]
struct TlsDecryptRequest {
    flow_id: String,
    packet_no: u64,
    client_random: String,
    record_hex: String,
}

#[derive(Debug, serde::Deserialize)]
struct TlsDecryptResponse {
    ok: bool,
    content_type: Option<String>,
    plaintext_hex: Option<String>,
    detail: Option<String>,
}

impl TlsTracker {
    pub fn ingest(&mut self, pkt: &Packet) {
        let Some(record) = tcp_complete_segment_payload(pkt).and_then(|(_, bytes)| first_tls_record(bytes)) else {
            return;
        };
        let Some(flow_id) = StreamKey::from_packet(pkt).map(|key| key.id()) else { return; };
        let session = match (record[0], record.get(5).copied()) {
            (TLS_HANDSHAKE, Some(TLS_CLIENT_HELLO)) if complete_hello(record) => {
                let Some(profile) = parse_client_hello(record, 't') else { return; };
                let key_material = self.key_shelf.has_client_random(&profile.client_random);
                let session = self.session_for_observation(flow_id, pkt.timestamp);
                if session.client_random.as_ref().is_some_and(|prior| *prior != profile.client_random) {
                    *session = TlsSession {
                        flow_id: std::mem::take(&mut session.flow_id),
                        first_seen: pkt.timestamp,
                        ..Default::default()
                    };
                }
                session.offered_version = Some(tls_version_code(profile.negotiated_version));
                session.sni = profile.sni;
                session.alpn = profile.alpn;
                session.client_random = Some(profile.client_random);
                session.ja4 = Some(profile.ja4);
                session.ech_offered = profile.ech_offered;
                session.key_material = key_material;
                session
            }
            (TLS_HANDSHAKE, Some(TLS_SERVER_HELLO)) => {
                let Some((version, cipher)) = parse_anchored_server_hello(record) else { return; };
                let session = self.session_for_observation(flow_id, pkt.timestamp);
                session.tls_version = Some(tls_version_code(version));
                session.cipher_suite = Some(cipher);
                session
            }
            (0x15, Some(_)) if record.len() == 7 && matches!(record[5], 1 | 2) => {
                let session = self.session_for_observation(flow_id, pkt.timestamp);
                session.alert_level = Some(record[5]);
                session.alert_desc = Some(record[6]);
                session
            }
            (TLS_APPLICATION_DATA, Some(_)) => {
                let Some(decoded) = self.decrypt_record_with_helper(&flow_id, pkt.no, record) else { return; };
                let Some(session) = self.sessions.get_mut(&flow_id) else { return; };
                session.decrypted_records.push(decoded);
                if session.decrypted_records.len() > 100 {
                    session.decrypted_records.remove(0);
                }
                session
            }
            _ => return,
        };
        if session.packet_numbers.back() != Some(&pkt.no) {
            if session.packet_numbers.len() == MAX_PACKET_LINKS {
                session.packet_numbers.pop_front();
            }
            session.packet_numbers.push_back(pkt.no);
        }

        // Evict if over cap
        if self.sessions.len() > MAX_SESSIONS {
            if let Some(oldest) = self.sessions.iter()
                .min_by(|a, b| a.1.first_seen.total_cmp(&b.1.first_seen))
                .map(|(k, _)| k.clone())
            {
                self.sessions.remove(&oldest);
            }
        }
    }

    fn session_for_observation(&mut self, flow_id: String, timestamp: f64) -> &mut TlsSession {
        self.sessions.entry(flow_id.clone()).or_insert_with(|| TlsSession {
            flow_id, first_seen: timestamp, ..Default::default()
        })
    }

    /// Directly insert a pre-built session (used for scenario/demo seeding).
    pub fn insert(&mut self, session: TlsSession) {
        if self.sessions.len() < MAX_SESSIONS {
            self.sessions.insert(session.flow_id.clone(), session);
        }
    }

    pub fn get(&self, flow_id: &str) -> Option<&TlsSession> { self.sessions.get(flow_id) }

    pub fn for_packet(&self, packet: &Packet) -> Option<&TlsSession> {
        let session = self.get(&StreamKey::from_packet(packet)?.id())?;
        session.packet_numbers.contains(&packet.no).then_some(session)
    }

    pub fn all(&self) -> Vec<&TlsSession> {
        let mut v: Vec<_> = self.sessions.values().collect();
        v.sort_by(|a, b| b.first_seen.total_cmp(&a.first_seen));
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

    pub fn load_key_log(&mut self, path: impl AsRef<Path>) -> Result<usize, String> {
        let count = self.key_shelf.load(path)?;
        self.apply_key_material();
        Ok(count)
    }

    pub fn reload_key_log(&mut self) -> Result<usize, String> {
        let count = self.key_shelf.reload()?;
        self.apply_key_material();
        Ok(count)
    }

    fn apply_key_material(&mut self) {
        for session in self.sessions.values_mut() {
            session.key_material = session.client_random.as_deref()
                .is_some_and(|random| self.key_shelf.has_client_random(random));
        }
    }

    fn decrypt_record_with_helper(
        &mut self,
        flow_id: &str,
        packet_no: u64,
        record: &[u8],
    ) -> Option<DecryptedTlsRecord> {
        let session = self.sessions.get(flow_id)?;
        if !session.key_material { return None; }
        let client_random = session.client_random.clone()?;
        let helper = self.decrypt_helper_path.clone()?;
        let request = TlsDecryptRequest {
            flow_id: flow_id.to_string(),
            packet_no,
            client_random,
            record_hex: hex(record),
        };
        if self.decrypt_helper.as_ref().is_none_or(|running| running.program() != helper) {
            self.decrypt_helper = JsonLineHelper::spawn(&helper, "TLS decrypt").ok();
        }
        let result = self.decrypt_helper.as_mut()?.request::<_, TlsDecryptResponse>(&request)
            .and_then(|response| decode_tls_response(response, packet_no));
        if result.is_err() { self.decrypt_helper = None; }
        result.ok()
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn first_tls_record(payload: &[u8]) -> Option<&[u8]> {
    let &[kind, 3, version, high, low] = payload.first_chunk::<5>()? else { return None; };
    if !matches!(kind, TLS_HANDSHAKE | TLS_APPLICATION_DATA | 0x15) || version > 3 {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([high, low]));
    let limit = if kind == TLS_APPLICATION_DATA { 18_432 } else { 16_384 };
    (length <= limit).then(|| payload.get(..5 + length)).flatten()
}

fn complete_hello(record: &[u8]) -> bool {
    let Some(&[_, a, b, c]) = record.get(5..).and_then(|body| body.first_chunk::<4>()) else { return false; };
    record.len() - 9 >= u32::from_be_bytes([0, a, b, c]) as usize
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

fn tls_version_code(version: u16) -> String {
    tls_version_str((version >> 8) as u8, version as u8)
}

fn decode_tls_response(response: TlsDecryptResponse, packet_no: u64) -> Result<DecryptedTlsRecord, String> {
    if !response.ok {
        return Err(response.detail.unwrap_or_else(|| "TLS decrypt helper did not authenticate record".into()));
    }
    Ok(DecryptedTlsRecord {
        packet_no,
        content_type: response.content_type.unwrap_or_else(|| "application_data".into()),
        plaintext: decode_hex(&response.plaintext_hex.ok_or("TLS decrypt helper response missing plaintext_hex")?)
            .ok_or("TLS decrypt helper returned invalid plaintext_hex")?,
        detail: response.detail.unwrap_or_else(|| "authenticated by helper".into()),
    })
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 { return None; }
    (0..value.len()).step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

#[cfg(test)]
#[path = "../../tests/unit/analysis_tls_tests.rs"]
mod tests;
