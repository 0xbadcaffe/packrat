//! Correlated investigation scenario — seeds all analysis tabs with a coherent
//! "Operation Quiet Beacon" dataset so every tab shows meaningful, related data
//! in demo / simulated mode.
//!
//! Scenario summary:
//! - 192.168.1.50  victim workstation (Windows/7 TTL)
//! - 192.168.1.1   gateway router
//! - 203.0.113.7   C2 server (in IOC list) → beacon every ~30 s
//! - 8.8.8.8       DNS resolver
//! - High-entropy DNS subdomains  → DNS tunnel detection
//! - HTTP POST with cleartext credentials
//! - TLS to C2 with RC4 cipher (TLS weakness detection)
//! - Kerberos AS-REQ spray (brute-force)
//! - Carved PE from reassembled HTTP stream
//! - Pre-populated notebook notes + host tags

use crate::net::packet::Packet;

// ─── IP constants ─────────────────────────────────────────────────────────────
const VICTIM:  &str = "192.168.1.50";
const GATEWAY: &str = "192.168.1.1";
const C2:      &str = "203.0.113.7";
const DNS_SVR: &str = "8.8.8.8";
const INTRA_A: &str = "192.168.1.20";  // IT workstation
const INTRA_B: &str = "192.168.1.30";  // printer / service host

// ─── Packet factories ────────────────────────────────────────────────────────

fn pkt(no: u64, ts: f64, src: &str, dst: &str, proto: &str,
       sp: Option<u16>, dp: Option<u16>, info: &str, len: u16) -> Packet {
    Packet {
        no,
        timestamp: ts,
        src: src.into(),
        dst: dst.into(),
        protocol: proto.into(),
        length:   len,
        info:     info.into(),
        src_port: sp,
        dst_port: dp,
        vlan_id:  None,
        bytes:    make_bytes(len, proto),
    }
}

fn make_bytes(len: u16, proto: &str) -> Vec<u8> {
    let mut b: Vec<u8> = vec![0u8; len as usize];
    // Ethernet dst/src
    b[0..6].copy_from_slice(&[0xff,0xff,0xff,0xff,0xff,0xff]);
    b[6..12].copy_from_slice(&[0x00,0x1a,0x2b,0x3c,0x4d,0x5e]);
    // EtherType = IPv4
    b[12] = 0x08; b[13] = 0x00;
    // IP version/IHL
    b[14] = 0x45;
    // TTL — Windows-style 128 for victim
    if len > 22 { b[22] = 128; }
    // Sprinkle printable ASCII in payload to exercise Strings tab
    let payload_start = 54usize;
    let strings: &[u8] = match proto {
        "HTTP"     => b"POST /beacon HTTP/1.1\r\nAuthorization: Basic YWRtaW46cGFzczEyMw==\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        "DNS"      => b"high-entropy-aabbccdd.evil-tunnel.com\x00",
        "FTP"      => b"USER administrator\r\nPASS Password123!\r\n",
        "Kerberos" => b"AS-REQ user=administrator@CORP.EXAMPLE.COM\x00",
        _          => b"packrat-test-payload-string\x00",
    };
    if payload_start + strings.len() <= b.len() {
        b[payload_start..payload_start + strings.len()].copy_from_slice(strings);
    }
    b
}

// ─── Public interface ────────────────────────────────────────────────────────

/// Return the full correlated scenario packet list.
/// Call this once at startup in simulated mode and ingest all packets.
pub fn build() -> Vec<Packet> {
    let mut pkts = Vec::new();
    let mut no = 1u64;
    let mut ts = 1.0f64;

    macro_rules! add {
        ($src:expr, $dst:expr, $proto:expr, $sp:expr, $dp:expr, $info:expr, $len:expr) => {{
            pkts.push(pkt(no, ts, $src, $dst, $proto, $sp, $dp, $info, $len));
            no += 1;
            ts += 0.05;
        }};
    }

    // ── ARP / network discovery ────────────────────────────────────────────────
    add!(VICTIM,  "ff:ff:ff:ff:ff:ff", "ARP",  None,        None,        "Who has 192.168.1.1? Tell 192.168.1.50",       42);
    add!(GATEWAY, VICTIM,              "ARP",  None,        None,        "192.168.1.1 is at 00:11:22:33:44:55",          42);

    // ── DNS — normal + high-entropy tunnel queries ─────────────────────────────
    add!(VICTIM, DNS_SVR, "DNS", Some(54321), Some(53), "Query 0x1234 A google.com",                       74);
    add!(DNS_SVR, VICTIM, "DNS", Some(53),    Some(54321), "Response A 142.250.80.46",                    90);
    add!(VICTIM, DNS_SVR, "DNS", Some(54322), Some(53), "Query 0xabcd A aaabbbccc111222333.evil-tunnel.com",  120);
    add!(VICTIM, DNS_SVR, "DNS", Some(54323), Some(53), "Query 0xabce A dddeeefff444555666.evil-tunnel.com",  120);
    add!(VICTIM, DNS_SVR, "DNS", Some(54324), Some(53), "Query 0xabcf A ggghhh777888999aaa.evil-tunnel.com",  120);
    add!(VICTIM, DNS_SVR, "DNS", Some(54325), Some(53), "Query 0xabd0 A bbbccc000ddd111eee.evil-tunnel.com",  120);
    add!(VICTIM, DNS_SVR, "DNS", Some(54326), Some(53), "Query 0xabd1 A fffggg222hhh333iii.evil-tunnel.com",  120);

    // ── HTTP with cleartext credentials ───────────────────────────────────────
    add!(VICTIM, INTRA_A, "HTTP", Some(49152), Some(80),
         "POST /admin/login HTTP/1.1 Host: intranet.corp Authorization: Basic YWRtaW46cGFzczEyMw==", 512);
    add!(INTRA_A, VICTIM, "HTTP", Some(80), Some(49152),
         "HTTP/1.1 200 OK Server: Apache", 256);
    add!(VICTIM, INTRA_A, "HTTP", Some(49153), Some(80),
         "GET /api/v1/users HTTP/1.1 Host: intranet.corp", 400);

    // ── FTP with cleartext credentials ────────────────────────────────────────
    add!(VICTIM, INTRA_B, "FTP", Some(49200), Some(21),
         "FTP Request: USER administrator", 80);
    add!(VICTIM, INTRA_B, "FTP", Some(49200), Some(21),
         "FTP Request: PASS Password123!", 80);

    // ── Beacon traffic to C2 (30 packets at ~30s intervals) ───────────────────
    for i in 0..30u64 {
        let beacon_ts = ts + (i as f64) * 30.0;
        pkts.push(pkt(no, beacon_ts, VICTIM, C2, "TCP",
            Some(50000 + i as u16), Some(4444),
            &format!("TCP → 4444 [PSH, ACK] Seq={} Len=64", i * 64),
            118));
        no += 1;
        pkts.push(pkt(no, beacon_ts + 0.02, C2, VICTIM, "TCP",
            Some(4444), Some(50000 + i as u16),
            &format!("TCP → {} [ACK]", 50000 + i),
            60));
        no += 1;
    }
    ts += 30.0 * 30.0;

    // ── TLS to C2 with weak RC4 cipher ────────────────────────────────────────
    add!(VICTIM, C2, "TLS", Some(51000), Some(443),
         "TLS Client Hello SNI=c2.evil-tunnel.com cipher=RC4-MD5", 220);
    add!(C2, VICTIM, "TLS", Some(443), Some(51000),
         "TLS Server Hello cipher=RC4-MD5", 180);
    add!(C2, VICTIM, "TLS", Some(443), Some(51000),
         "TLS Certificate CN=self-signed issuer=self-signed expires=2099-01-01", 800);
    add!(VICTIM, C2, "TLS", Some(51000), Some(443),
         "TLS Application Data", 128);

    // ── Kerberos brute-force spray ─────────────────────────────────────────────
    for user in &["administrator", "backup_svc", "svc_sql", "helpdesk", "john.smith"] {
        add!(VICTIM, INTRA_A, "Kerberos", Some(49300), Some(88),
             &format!("Kerberos AS-REQ user={}@CORP.EXAMPLE.COM", user), 180);
        add!(INTRA_A, VICTIM, "Kerberos", Some(88), Some(49300),
             "Kerberos KRB5KDC_ERR_PREAUTH_REQUIRED", 100);
    }

    // ── Internal lateral movement (SMB) ───────────────────────────────────────
    add!(VICTIM, INTRA_A, "SMB", Some(49400), Some(445),
         "SMB2 Negotiate", 120);
    add!(VICTIM, INTRA_A, "SMB", Some(49401), Some(445),
         "SMB2 SessionSetup user=administrator", 200);
    add!(VICTIM, INTRA_A, "SMB", Some(49402), Some(445),
         "SMB2 TreeConnect path=\\\\intranet\\C$", 160);
    add!(VICTIM, INTRA_A, "SMB", Some(49403), Some(445),
         "SMB2 Create file=\\Windows\\System32\\evil.exe", 200);

    // ── Additional diverse traffic to populate other tabs ─────────────────────
    add!(VICTIM,  GATEWAY, "ICMP", None, None,
         "Echo request id=0x0001 seq=1", 98);
    add!(GATEWAY, VICTIM,  "ICMP", None, None,
         "Echo reply id=0x0001 seq=1", 98);
    add!(VICTIM, "10.10.1.5", "Modbus", Some(49500), Some(502),
         "FC3 Read Holding Registers unit=1 addr=0x0000", 80);
    add!("10.10.1.5", VICTIM, "Modbus", Some(502), Some(49500),
         "FC3 Response 4 registers", 72);
    add!(VICTIM, "10.10.1.5", "MQTT", Some(49501), Some(1883),
         "MQTT PUBLISH topic=sensors/temperature qos=0 len=4", 60);
    add!(VICTIM, GATEWAY, "NTP", Some(49502), Some(123),
         "NTP v4 client stratum=0", 76);
    add!(INTRA_A, INTRA_B, "HTTP", Some(49600), Some(8080),
         "GET /metrics HTTP/1.1 Host: 192.168.1.30", 300);

    let _ = (no, ts); // consumed by macro post-increment on last call
    pkts
}

// ─── Tab-specific seed data ──────────────────────────────────────────────────

/// TLS sessions covering weak ciphers, self-signed certs, expired certs, TLS 1.0/1.1.
pub fn tls_sessions() -> Vec<crate::analysis::tls::TlsSession> {
    use crate::analysis::tls::TlsSession;
    vec![
        TlsSession {
            flow_id:        format!("{}:51000-{}:443", VICTIM, C2),
            sni:            Some("c2.evil-tunnel.com".into()),
            cipher_suite:   Some(0x0005), // RC4-SHA (WEAK)
            tls_version:    Some("TLS 1.2".into()),
            ja3:            Some("a0e9f5d64349fb13191bc781f81f42e1".into()),
            ja3s:           Some("ec74a5c51106f0419184d0dd08fb05bc".into()),
            cert_cn:        Some("evil-tunnel.com".into()),
            cert_san:       vec!["evil-tunnel.com".into(), "c2.evil-tunnel.com".into()],
            cert_issuer:    Some("self-signed".into()),
            cert_not_after: Some("2099-01-01".into()),
            first_seen:     1.0,
            alert_level:    None,
            alert_desc:     None,
        },
        TlsSession {
            flow_id:        format!("{}:51001-{}:443", VICTIM, INTRA_A),
            sni:            Some("intranet.corp".into()),
            cipher_suite:   Some(0x000A), // 3DES-CBC-SHA (WEAK)
            tls_version:    Some("TLS 1.0".into()),
            ja3:            Some("de350869b8c85de67a350c8d186f11e6".into()),
            ja3s:           Some("fd4bc6cea4877646ccd62f0792ec0b62".into()),
            cert_cn:        Some("intranet.corp".into()),
            cert_san:       vec!["intranet.corp".into(), "www.intranet.corp".into()],
            cert_issuer:    Some("CORP Internal CA".into()),
            cert_not_after: Some("2020-06-01".into()), // expired
            first_seen:     2.5,
            alert_level:    None,
            alert_desc:     None,
        },
        TlsSession {
            flow_id:        format!("{}:51002-8.8.8.8:853", VICTIM),
            sni:            Some("dns.google".into()),
            cipher_suite:   Some(0x1302), // TLS_AES_256_GCM_SHA384
            tls_version:    Some("TLS 1.3".into()),
            ja3:            Some("cd08e31494f9531f560d64c695473da9".into()),
            ja3s:           Some("fa5674e5a060e56a53ed6e74992e854d".into()),
            cert_cn:        Some("dns.google".into()),
            cert_san:       vec!["dns.google".into(), "8.8.8.8".into()],
            cert_issuer:    Some("GTS CA 1C3".into()),
            cert_not_after: Some("2026-01-15".into()),
            first_seen:     3.0,
            alert_level:    None,
            alert_desc:     None,
        },
        TlsSession {
            flow_id:        format!("{}:51003-104.16.0.1:443", VICTIM),
            sni:            Some("api.github.com".into()),
            cipher_suite:   Some(0xC02F), // ECDHE-RSA-AES128-GCM-SHA256
            tls_version:    Some("TLS 1.2".into()),
            ja3:            Some("771,4866-4867-4865-49196,0-23-65281,29-23-24,0".into()),
            ja3s:           Some("ec74a5c51106f0419184d0dd08fb05bc".into()),
            cert_cn:        Some("github.com".into()),
            cert_san:       vec!["github.com".into(), "*.github.com".into()],
            cert_issuer:    Some("DigiCert TLS RSA SHA256 2020 CA1".into()),
            cert_not_after: Some("2026-03-17".into()),
            first_seen:     4.0,
            alert_level:    None,
            alert_desc:     None,
        },
        TlsSession {
            flow_id:        format!("{}:51004-23.0.0.1:443", INTRA_A),
            sni:            Some("update.microsoft.com".into()),
            cipher_suite:   Some(0x1301), // TLS_AES_128_GCM_SHA256
            tls_version:    Some("TLS 1.3".into()),
            ja3:            Some("771,4866-4867-4865-49196,0-23-65281,29-23-24,0".into()),
            ja3s:           None,
            cert_cn:        Some("update.microsoft.com".into()),
            cert_san:       vec!["update.microsoft.com".into()],
            cert_issuer:    Some("Microsoft Azure TLS Issuing CA 01".into()),
            cert_not_after: Some("2026-09-20".into()),
            first_seen:     5.5,
            alert_level:    None,
            alert_desc:     None,
        },
        TlsSession {
            flow_id:        format!("{}:51005-{}:8443", VICTIM, INTRA_B),
            sni:            Some("printer.corp".into()),
            cipher_suite:   Some(0x0004), // RC4-MD5 (WEAK)
            tls_version:    Some("TLS 1.1".into()),
            ja3:            Some("b32309a26951912be7dba376398abc3b".into()),
            ja3s:           None,
            cert_cn:        Some("HP LaserJet Pro".into()),
            cert_san:       vec![],
            cert_issuer:    Some("self-signed".into()),
            cert_not_after: Some("2018-12-31".into()), // expired 2018
            first_seen:     6.0,
            alert_level:    Some(2),  // fatal alert
            alert_desc:     Some(42), // bad_certificate
        },
    ]
}

/// Security engine seed data — IDS alerts, OS guesses, ARP anomalies, brute force,
/// HTTP records, TLS weaknesses, DNS tunnel suspects, vuln hits.
pub fn security_seed() -> ScenarioSecurityData {
    use crate::net::security::*;
    ScenarioSecurityData {
        ids_alerts: vec![
            IdsAlert { pkt_no: 3,  signature: "ET SCAN Nmap SYN Scan",
                severity: Severity::Medium, detail: "SYN scan from 192.168.1.50 → multiple ports".into() },
            IdsAlert { pkt_no: 8,  signature: "ET WEB_SERVER SQL Injection Attempt",
                severity: Severity::High, detail: "POST /admin/login — possible SQLi in auth field".into() },
            IdsAlert { pkt_no: 19, signature: "ET MALWARE Cobalt Strike Beacon",
                severity: Severity::Critical, detail: "C2 beacon pattern — 64-byte PSH/ACK to 203.0.113.7:4444".into() },
            IdsAlert { pkt_no: 41, signature: "ET POLICY Weak TLS Cipher RC4",
                severity: Severity::High, detail: "RC4-SHA negotiated to 203.0.113.7".into() },
            IdsAlert { pkt_no: 48, signature: "ET EXPLOIT MS17-010 EternalBlue",
                severity: Severity::Critical, detail: "SMB buffer overflow pattern to 192.168.1.20:445".into() },
            IdsAlert { pkt_no: 50, signature: "ET SCAN Kerberos AS-REQ Spray",
                severity: Severity::High, detail: "5 AS-REQ to different accounts within 0.5s".into() },
            IdsAlert { pkt_no: 57, signature: "ET LATERAL SMB Admin Share Access",
                severity: Severity::High, detail: "TreeConnect to \\intranet\\C$ by non-admin user".into() },
            IdsAlert { pkt_no: 62, signature: "ET EXFIL DNS Tunnel Suspected",
                severity: Severity::Medium, detail: "High-entropy subdomain queries to evil-tunnel.com".into() },
        ],
        arp_anomalies: vec![
            ArpAnomaly { pkt_no: 1, ip: GATEWAY.into(),
                old_mac: "00:11:22:33:44:55".into(), new_mac: "de:ad:be:ef:00:01".into() },
            ArpAnomaly { pkt_no: 2, ip: INTRA_A.into(),
                old_mac: "aa:bb:cc:dd:ee:ff".into(), new_mac: "de:ad:be:ef:00:02".into() },
        ],
        os_guesses: vec![
            OsGuess { src_ip: VICTIM.into(),  os: "Windows 10 (TTL=128)", ttl: 128, window: 65535 },
            OsGuess { src_ip: C2.into(),      os: "Linux 4.x (TTL=64)",   ttl: 64,  window: 29200 },
            OsGuess { src_ip: INTRA_A.into(), os: "Linux 5.x (TTL=64)",   ttl: 64,  window: 65160 },
            OsGuess { src_ip: INTRA_B.into(), os: "Embedded/IoT (TTL=64)",ttl: 64,  window: 4096  },
        ],
        vuln_hits: vec![
            VulnHit { pkt_no: 48, kind: "EternalBlue (MS17-010)",
                detail: "SMBv1 exploit pattern — TRANS2 SESSION_SETUP overwrite".into() },
            VulnHit { pkt_no: 41, kind: "POODLE / SSL3 Fallback",
                detail: "TLS 1.0 negotiated with RC4 — susceptible to BEAST/POODLE".into() },
            VulnHit { pkt_no: 8,  kind: "Cleartext Authentication",
                detail: "HTTP Basic Auth credential sent unencrypted (port 80)".into() },
            VulnHit { pkt_no: 13, kind: "FTP Cleartext Credential",
                detail: "FTP PASS command visible in cleartext on port 21".into() },
        ],
        brute_force: vec![
            BruteForceAlert { src_ip: VICTIM.into(), dst_ip: INTRA_A.into(),
                port: 88,  attempts: 5,  service: "Kerberos" },
            BruteForceAlert { src_ip: VICTIM.into(), dst_ip: INTRA_A.into(),
                port: 80,  attempts: 12, service: "HTTP" },
            BruteForceAlert { src_ip: "10.10.1.99".into(), dst_ip: VICTIM.into(),
                port: 22,  attempts: 47, service: "SSH" },
            BruteForceAlert { src_ip: "10.10.1.99".into(), dst_ip: VICTIM.into(),
                port: 3389, attempts: 23, service: "RDP" },
        ],
        http_records: vec![
            HttpRecord { pkt_no: 8,  src_ip: VICTIM.into(), dst_ip: INTRA_A.into(), port: 80,
                method: "POST".into(), path: "/admin/login".into(),
                user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".into(),
                response_code: Some(200) },
            HttpRecord { pkt_no: 10, src_ip: VICTIM.into(), dst_ip: INTRA_A.into(), port: 80,
                method: "GET".into(), path: "/api/v1/users".into(),
                user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".into(),
                response_code: Some(200) },
            HttpRecord { pkt_no: 15, src_ip: "10.10.1.99".into(), dst_ip: VICTIM.into(), port: 80,
                method: "GET".into(), path: "/.env".into(),
                user_agent: "python-requests/2.28.0".into(),
                response_code: Some(200) },
            HttpRecord { pkt_no: 16, src_ip: "10.10.1.99".into(), dst_ip: VICTIM.into(), port: 80,
                method: "GET".into(), path: "/wp-admin/".into(),
                user_agent: "Nikto/2.1.6".into(),
                response_code: Some(302) },
            HttpRecord { pkt_no: 17, src_ip: "10.10.1.99".into(), dst_ip: VICTIM.into(), port: 80,
                method: "GET".into(), path: "/etc/passwd".into(),
                user_agent: "curl/7.85.0".into(),
                response_code: Some(403) },
        ],
        tls_weaknesses: vec![
            TlsWeakness { pkt_no: 41, src_ip: VICTIM.into(), dst_ip: C2.into(),
                kind: "Weak Cipher",
                detail: "RC4-SHA negotiated — broken stream cipher, no forward secrecy".into() },
            TlsWeakness { pkt_no: 42, src_ip: VICTIM.into(), dst_ip: INTRA_A.into(),
                kind: "Weak Cipher + Old Version",
                detail: "3DES-CBC-SHA on TLS 1.0 — SWEET32 vulnerable, BEAST attack surface".into() },
            TlsWeakness { pkt_no: 43, src_ip: VICTIM.into(), dst_ip: INTRA_B.into(),
                kind: "Self-Signed + Expired Certificate",
                detail: "cert CN=HP LaserJet Pro expired 2018-12-31, issuer=self-signed".into() },
            TlsWeakness { pkt_no: 44, src_ip: VICTIM.into(), dst_ip: C2.into(),
                kind: "Self-Signed Certificate",
                detail: "cert CN=evil-tunnel.com issued by self — no chain of trust".into() },
        ],
        dns_suspects: vec![
            DnsTunnelSuspect { apex: "evil-tunnel.com".into(),
                query_count: 127, max_entropy: 4.87, max_subdomain_len: 52,
                unique_subdomains: 89, score: 18.4 },
            DnsTunnelSuspect { apex: "dnscat2.attacker.net".into(),
                query_count: 34, max_entropy: 4.62, max_subdomain_len: 63,
                unique_subdomains: 31, score: 12.7 },
        ],
    }
}

/// Credential hits to pre-seed.
pub fn credentials() -> Vec<crate::net::inspector::CredentialHit> {
    use crate::net::inspector::CredentialHit;
    vec![
        CredentialHit { proto: "HTTP".into(), kind: "HTTP-BasicAuth",
            value: "admin:pass123 (base64: YWRtaW46cGFzczEyMw==)".into(), pkt_no: 8 },
        CredentialHit { proto: "FTP".into(),  kind: "FTP-USER",
            value: "administrator".into(), pkt_no: 12 },
        CredentialHit { proto: "FTP".into(),  kind: "FTP-PASS",
            value: "Password123!".into(), pkt_no: 13 },
        CredentialHit { proto: "HTTP".into(), kind: "HTTP-BasicAuth",
            value: "backup_svc:BackupPass2023! (base64: YmFja3VwX3N2YzpCYWNrdXBQYXNzMjAyMyE=)".into(), pkt_no: 17 },
        CredentialHit { proto: "SMTP".into(), kind: "SMTP-AUTH",
            value: "mailuser:SecretMail99".into(), pkt_no: 67 },
        CredentialHit { proto: "IMAP".into(), kind: "IMAP-LOGIN",
            value: "john.smith:Welcome1234".into(), pkt_no: 68 },
    ]
}

/// Carved objects to pre-seed in the Objects tab.
pub fn carved_objects() -> Vec<crate::analysis::carving::CarvedObject> {
    use crate::analysis::carving::CarvedObject;
    // Minimal realistic magic-byte prefixes so the type is recognisable.
    vec![
        CarvedObject {
            id: 1, kind: "application/exe".into(),
            name: "evil.exe (from SMB stream to \\\\intranet\\C$)".into(),
            source: "smb:192.168.1.50:49403-192.168.1.20:445".into(),
            offset: 0,
            data:   { let mut v = b"MZ\x90\x00\x03\x00\x00\x00".to_vec(); v.extend(vec![0u8; 512]); v },
            sha256: "4a5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d".into(),
            yara_hits: vec!["Trojan.CobaltStrike.Beacon".into(), "Malware.Generic.PE".into()],
        },
        CarvedObject {
            id: 2, kind: "application/elf".into(),
            name: "backdoor.elf (from TCP stream 203.0.113.7:4444)".into(),
            source: "tcp:192.168.1.50:50000-203.0.113.7:4444".into(),
            offset: 128,
            data:   { let mut v = b"\x7fELF\x02\x01\x01\x00".to_vec(); v.extend(vec![0u8; 768]); v },
            sha256: "7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c".into(),
            yara_hits: vec!["Linux.Backdoor.Mirai".into()],
        },
        CarvedObject {
            id: 3, kind: "application/pdf".into(),
            name: "invoice_Q4.pdf (from HTTP GET /docs)".into(),
            source: "http:192.168.1.50:49152-192.168.1.20:80".into(),
            offset: 0,
            data:   { let mut v = b"%PDF-1.4\n".to_vec(); v.extend(vec![0u8; 4096]); v.extend(b"%%EOF"); v },
            sha256: "1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d".into(),
            yara_hits: vec![],
        },
        CarvedObject {
            id: 4, kind: "application/zip".into(),
            name: "tools.zip (from FTP RETR)".into(),
            source: "ftp:192.168.1.50:49200-192.168.1.30:21".into(),
            offset: 0,
            data:   { let mut v = b"PK\x03\x04\x14\x00\x00\x00".to_vec(); v.extend(vec![0u8; 2048]); v },
            sha256: "9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b".into(),
            yara_hits: vec!["Suspicious.ArchiveTool".into()],
        },
        CarvedObject {
            id: 5, kind: "image/png".into(),
            name: "screenshot_2024.png (from HTTP response)".into(),
            source: "http:192.168.1.20:80-192.168.1.50:49153".into(),
            offset: 0,
            data:   { let mut v = b"\x89PNG\r\n\x1a\n".to_vec(); v.extend(vec![0u8; 1024]); v },
            sha256: "3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e".into(),
            yara_hits: vec![],
        },
    ]
}

/// Detection rules to load into the rule engine (seeded rules + pre-fired hits).
pub fn rules() -> Vec<(crate::analysis::rules::Rule, u64)> {
    use crate::analysis::rules::{Rule, Condition, Action, CmpOp};
    use crate::model::evidence::Severity;
    vec![
        (Rule {
            id: "rule-001".into(), name: "C2 Beacon Detection".into(),
            description: "TCP PSH/ACK to known C2 port 4444 at regular intervals".into(),
            enabled: true, hits: 30,
            condition: Condition::And(vec![
                Condition::Equals { field: "proto".into(),   value: "TCP".into() },
                Condition::Num    { field: "dstport".into(), op: CmpOp::Eq, value: 4444 },
            ]),
            actions: vec![Action::Alert { message: "C2 beacon to port 4444".into(), severity: Severity::Critical }],
        }, 30),
        (Rule {
            id: "rule-002".into(), name: "DNS Tunnel Detection".into(),
            description: "High-entropy subdomain queries indicative of DNS tunnelling".into(),
            enabled: true, hits: 5,
            condition: Condition::And(vec![
                Condition::Equals  { field: "proto".into(), value: "DNS".into() },
                Condition::Contains { field: "info".into(),  value: "evil-tunnel.com".into() },
            ]),
            actions: vec![
                Action::Alert { message: "DNS tunnel query detected".into(), severity: Severity::High },
                Action::Tag   { tag: "dns-tunnel".into() },
            ],
        }, 5),
        (Rule {
            id: "rule-003".into(), name: "Cleartext HTTP Credentials".into(),
            description: "HTTP Authorization header in plaintext (port 80)".into(),
            enabled: true, hits: 2,
            condition: Condition::And(vec![
                Condition::Equals  { field: "proto".into(), value: "HTTP".into() },
                Condition::Contains { field: "info".into(),  value: "Authorization".into() },
            ]),
            actions: vec![
                Action::Alert { message: "Cleartext credential in HTTP".into(), severity: Severity::High },
                Action::Log   { message: "Credential exposure — upgrade to HTTPS".into() },
            ],
        }, 2),
        (Rule {
            id: "rule-004".into(), name: "Kerberos AS-REQ Spray".into(),
            description: "Repeated Kerberos pre-auth requests — password spray indicator".into(),
            enabled: true, hits: 5,
            condition: Condition::And(vec![
                Condition::Equals  { field: "proto".into(), value: "Kerberos".into() },
                Condition::Contains { field: "info".into(),  value: "AS-REQ".into() },
            ]),
            actions: vec![Action::Alert { message: "Kerberos spray attempt".into(), severity: Severity::High }],
        }, 5),
        (Rule {
            id: "rule-005".into(), name: "SMB Admin Share Access".into(),
            description: "Connection to administrative C$ or ADMIN$ share".into(),
            enabled: true, hits: 1,
            condition: Condition::And(vec![
                Condition::Equals  { field: "proto".into(), value: "SMB".into() },
                Condition::Contains { field: "info".into(),  value: "C$".into() },
            ]),
            actions: vec![
                Action::Alert { message: "Lateral movement via SMB admin share".into(), severity: Severity::Critical },
                Action::Tag   { tag: "lateral-movement".into() },
            ],
        }, 1),
        (Rule {
            id: "rule-006".into(), name: "FTP Cleartext Password".into(),
            description: "FTP PASS command containing plaintext password".into(),
            enabled: true, hits: 1,
            condition: Condition::And(vec![
                Condition::Equals  { field: "proto".into(), value: "FTP".into() },
                Condition::Contains { field: "info".into(),  value: "PASS".into() },
            ]),
            actions: vec![Action::Alert { message: "Cleartext FTP credential".into(), severity: Severity::Medium }],
        }, 1),
        (Rule {
            id: "rule-007".into(), name: "OT Protocol Access (Modbus)".into(),
            description: "Modbus traffic to ICS/SCADA devices — monitor for anomalies".into(),
            enabled: true, hits: 1,
            condition: Condition::Equals { field: "proto".into(), value: "Modbus".into() },
            actions: vec![Action::Log { message: "Modbus FC3 register read — verify source is authorised".into() }],
        }, 1),
        (Rule {
            id: "rule-008".into(), name: "Large Frame Anomaly".into(),
            description: "Frames above 8KB may indicate data exfiltration or exploit".into(),
            enabled: false, hits: 0,
            condition: Condition::Num { field: "len".into(), op: CmpOp::Gt, value: 8192 },
            actions: vec![Action::Alert { message: "Oversized frame".into(), severity: Severity::Low }],
        }, 0),
    ]
}

pub struct ScenarioSecurityData {
    pub ids_alerts:     Vec<crate::net::security::IdsAlert>,
    pub arp_anomalies:  Vec<crate::net::security::ArpAnomaly>,
    pub os_guesses:     Vec<crate::net::security::OsGuess>,
    pub vuln_hits:      Vec<crate::net::security::VulnHit>,
    pub brute_force:    Vec<crate::net::security::BruteForceAlert>,
    pub http_records:   Vec<crate::net::security::HttpRecord>,
    pub tls_weaknesses: Vec<crate::net::security::TlsWeakness>,
    pub dns_suspects:   Vec<crate::net::security::DnsTunnelSuspect>,
}

/// Return the IOC IP list for the scenario (seeded into IocEngine on startup).
pub fn ioc_ips() -> Vec<&'static str> {
    vec![C2, "203.0.113.99", "198.51.100.7"]
}

/// Canonical scenario analyst notes to pre-populate Notebook.
pub fn notebook_notes() -> Vec<(&'static str, Option<&'static str>)> {
    vec![
        ("C2 IP 203.0.113.7 confirmed via DNS lookup correlation", Some("pkt#3")),
        ("DNS tunnel detected: high-entropy subdomains to evil-tunnel.com", Some("pkt#5")),
        ("Cleartext credentials extracted from HTTP POST to intranet", Some("pkt#8")),
        ("TLS RC4 cipher suite to C2 — known-weak, pre-TLS1.2", Some("pkt#41")),
        ("Kerberos AS-REQ spray: 5 accounts tried in < 1s", Some("pkt#50")),
        ("SMB lateral movement to 192.168.1.20 — accessed C$ share", Some("pkt#57")),
    ]
}

/// Host tags to pre-seed.
pub fn host_tags() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (VICTIM,  vec!["compromised", "victim", "priority-1"]),
        (C2,      vec!["c2", "ioc", "threat-actor"]),
        (INTRA_A, vec!["lateral-movement-target"]),
        (GATEWAY, vec!["infrastructure"]),
    ]
}
