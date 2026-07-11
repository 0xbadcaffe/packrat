//! TLS intelligence — SNI extraction, cipher suite tracking, JA3 fingerprinting.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use crate::analysis::helper_process::spawn_stdin_stdout_helper;
use crate::analysis::encrypted_insight::{parse_client_hello, parse_server_hello};
use crate::analysis::key_shelf::KeyShelf;
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

#[derive(Debug)]
pub struct TlsTracker {
    sessions: HashMap<String, TlsSession>,
    pub key_shelf: KeyShelf,
    pub decrypt_helper_path: Option<PathBuf>,
}

impl Default for TlsTracker {
    fn default() -> Self {
        Self { sessions: HashMap::new(), key_shelf: KeyShelf::default(), decrypt_helper_path: None }
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
        let flow_id = make_flow_id(pkt);
        if let Some(profile) = parse_client_hello(&pkt.bytes, 't') {
            let key_material = self.key_shelf.has_client_random(&profile.client_random);
            let session = self.sessions.entry(flow_id.clone()).or_insert_with(|| TlsSession {
                flow_id: flow_id.clone(),
                first_seen: pkt.timestamp,
                ..Default::default()
            });
            session.tls_version = Some(tls_version_code(profile.negotiated_version));
            session.sni = profile.sni;
            session.alpn = profile.alpn;
            session.client_random = Some(profile.client_random);
            session.ja4 = Some(profile.ja4);
            session.ech_offered = profile.ech_offered;
            session.key_material = key_material;
        } else if let Some((version, cipher)) = parse_server_hello(&pkt.bytes) {
            let session = self.sessions.entry(flow_id.clone()).or_insert_with(|| TlsSession {
                flow_id: flow_id.clone(),
                first_seen: pkt.timestamp,
                ..Default::default()
            });
            if session.tls_version.is_none() { session.tls_version = Some(tls_version_code(version)); }
            session.cipher_suite = Some(cipher);
        } else if let Some(position) = pkt.bytes.windows(7).position(|window| window[0] == 0x15 && window[1] == 0x03) {
            let session = self.sessions.entry(flow_id.clone()).or_insert_with(|| TlsSession {
                flow_id: flow_id.clone(),
                first_seen: pkt.timestamp,
                ..Default::default()
            });
            session.alert_level = pkt.bytes.get(position + 5).copied();
            session.alert_desc = pkt.bytes.get(position + 6).copied();
        } else if let Some(record) = find_tls_record(&pkt.bytes, TLS_APPLICATION_DATA) {
            if let Some(decoded) = self.decrypt_record_with_helper(&flow_id, pkt.no, record) {
                if let Some(session) = self.sessions.get_mut(&flow_id) {
                    session.decrypted_records.push(decoded);
                    if session.decrypted_records.len() > 100 {
                        session.decrypted_records.remove(0);
                    }
                }
            }
        } else {
            return;
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
        &self,
        flow_id: &str,
        packet_no: u64,
        record: &[u8],
    ) -> Option<DecryptedTlsRecord> {
        let session = self.sessions.get(flow_id)?;
        if !session.key_material { return None; }
        let client_random = session.client_random.clone()?;
        let helper = self.decrypt_helper_path.as_ref()?;
        let request = TlsDecryptRequest {
            flow_id: flow_id.to_string(),
            packet_no,
            client_random,
            record_hex: hex(record),
        };
        run_tls_decrypt_helper(helper, &request).ok()
    }
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

fn tls_version_code(version: u16) -> String {
    tls_version_str((version >> 8) as u8, version as u8)
}

fn find_tls_record(raw: &[u8], record_type: u8) -> Option<&[u8]> {
    let start = raw.windows(5).position(|window| window[0] == record_type && window[1] == 0x03)?;
    let len = u16::from_be_bytes([*raw.get(start + 3)?, *raw.get(start + 4)?]) as usize;
    raw.get(start..start + 5 + len)
}

fn run_tls_decrypt_helper(helper: &Path, request: &TlsDecryptRequest) -> Result<DecryptedTlsRecord, String> {
    let mut child = spawn_stdin_stdout_helper(helper, "TLS decrypt")?;
    let input = serde_json::to_vec(request)
        .map_err(|error| format!("encode TLS decrypt helper request: {error}"))?;
    child.stdin.as_mut().ok_or("TLS decrypt helper stdin unavailable")?
        .write_all(&input).map_err(|error| format!("write TLS decrypt helper request: {error}"))?;
    let output = child.wait_with_output().map_err(|error| format!("wait for TLS decrypt helper: {error}"))?;
    if !output.status.success() {
        return Err(format!("TLS decrypt helper failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    let response: TlsDecryptResponse = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("decode TLS decrypt helper response: {error}"))?;
    if !response.ok {
        return Err(response.detail.unwrap_or_else(|| "TLS decrypt helper did not authenticate record".into()));
    }
    Ok(DecryptedTlsRecord {
        packet_no: request.packet_no,
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
mod tests {
    use super::*;

    fn packet(bytes: Vec<u8>) -> Packet {
        Packet {
            no: 9,
            timestamp: 9.0,
            src: "192.0.2.10".into(),
            dst: "198.51.100.7".into(),
            protocol: "TLS".into(),
            length: bytes.len() as u16,
            info: String::new(),
            src_port: Some(50000),
            dst_port: Some(443),
            vlan_id: None,
            vlan_pcp: None,
            vlan_dei: None,
            outer_vlan_id: None,
            bytes,
        }
    }

    #[cfg(unix)]
    #[test]
    fn helper_authenticated_tls_record_is_retained() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!("packrat-tls-helper-{}-{}.sh", std::process::id(), unique_test_suffix()));
        std::fs::write(
            &path,
            "#!/bin/sh\ncat >/dev/null\nprintf '{\"ok\":true,\"content_type\":\"http\",\"plaintext_hex\":\"474554202f20485454502f312e31\",\"detail\":\"auth ok\"}'\n",
        ).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).unwrap();

        let mut tracker = TlsTracker::default();
        tracker.decrypt_helper_path = Some(path.clone());
        tracker.insert(TlsSession {
            flow_id: "192.0.2.10:50000-198.51.100.7:443".into(),
            client_random: Some("00".repeat(32)),
            key_material: true,
            first_seen: 1.0,
            ..Default::default()
        });
        tracker.ingest(&packet(vec![0x17, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4]));
        let session = tracker.get("192.0.2.10:50000-198.51.100.7:443").unwrap();
        assert_eq!(session.decrypted_records.len(), 1);
        assert_eq!(session.decrypted_records[0].plaintext, b"GET / HTTP/1.1");
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    fn unique_test_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    }
}
