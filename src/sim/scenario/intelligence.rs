use super::*;

// ─── Tab-specific seed data ──────────────────────────────────────────────────

/// TLS sessions covering weak ciphers, self-signed certs, expired certs, TLS 1.0/1.1.
pub fn tls_sessions() -> Vec<crate::analysis::tls::TlsSession> {
    use crate::analysis::tls::TlsSession;
    vec![
        TlsSession {
            flow_id: format!("{}:51000-{}:443", VICTIM, C2),
            sni: Some("c2.evil-tunnel.com".into()),
            cipher_suite: Some(0x0005), // RC4-SHA (WEAK)
            tls_version: Some("TLS 1.2".into()),
            ja3: Some("a0e9f5d64349fb13191bc781f81f42e1".into()),
            ja3s: Some("ec74a5c51106f0419184d0dd08fb05bc".into()),
            cert_cn: Some("evil-tunnel.com".into()),
            cert_san: vec!["evil-tunnel.com".into(), "c2.evil-tunnel.com".into()],
            cert_issuer: Some("self-signed".into()),
            cert_not_after: Some("2099-01-01".into()),
            first_seen: 1.0,
            alert_level: None,
            alert_desc: None,
            ..Default::default()
        },
        TlsSession {
            flow_id: format!("{}:51001-{}:443", VICTIM, INTRA_A),
            sni: Some("intranet.corp".into()),
            cipher_suite: Some(0x000A), // 3DES-CBC-SHA (WEAK)
            tls_version: Some("TLS 1.0".into()),
            ja3: Some("de350869b8c85de67a350c8d186f11e6".into()),
            ja3s: Some("fd4bc6cea4877646ccd62f0792ec0b62".into()),
            cert_cn: Some("intranet.corp".into()),
            cert_san: vec!["intranet.corp".into(), "www.intranet.corp".into()],
            cert_issuer: Some("CORP Internal CA".into()),
            cert_not_after: Some("2020-06-01".into()), // expired
            first_seen: 2.5,
            alert_level: None,
            alert_desc: None,
            ..Default::default()
        },
        TlsSession {
            flow_id: format!("{}:51002-8.8.8.8:853", VICTIM),
            sni: Some("dns.google".into()),
            cipher_suite: Some(0x1302), // TLS_AES_256_GCM_SHA384
            tls_version: Some("TLS 1.3".into()),
            ja3: Some("cd08e31494f9531f560d64c695473da9".into()),
            ja3s: Some("fa5674e5a060e56a53ed6e74992e854d".into()),
            cert_cn: Some("dns.google".into()),
            cert_san: vec!["dns.google".into(), "8.8.8.8".into()],
            cert_issuer: Some("GTS CA 1C3".into()),
            cert_not_after: Some("2026-01-15".into()),
            first_seen: 3.0,
            alert_level: None,
            alert_desc: None,
            ..Default::default()
        },
        TlsSession {
            flow_id: format!("{}:51003-104.16.0.1:443", VICTIM),
            sni: Some("api.github.com".into()),
            cipher_suite: Some(0xC02F), // ECDHE-RSA-AES128-GCM-SHA256
            tls_version: Some("TLS 1.2".into()),
            ja3: Some("771,4866-4867-4865-49196,0-23-65281,29-23-24,0".into()),
            ja3s: Some("ec74a5c51106f0419184d0dd08fb05bc".into()),
            cert_cn: Some("github.com".into()),
            cert_san: vec!["github.com".into(), "*.github.com".into()],
            cert_issuer: Some("DigiCert TLS RSA SHA256 2020 CA1".into()),
            cert_not_after: Some("2026-03-17".into()),
            first_seen: 4.0,
            alert_level: None,
            alert_desc: None,
            ..Default::default()
        },
        TlsSession {
            flow_id: format!("{}:51004-23.0.0.1:443", INTRA_A),
            sni: Some("update.microsoft.com".into()),
            cipher_suite: Some(0x1301), // TLS_AES_128_GCM_SHA256
            tls_version: Some("TLS 1.3".into()),
            ja3: Some("771,4866-4867-4865-49196,0-23-65281,29-23-24,0".into()),
            ja3s: None,
            cert_cn: Some("update.microsoft.com".into()),
            cert_san: vec!["update.microsoft.com".into()],
            cert_issuer: Some("Microsoft Azure TLS Issuing CA 01".into()),
            cert_not_after: Some("2026-09-20".into()),
            first_seen: 5.5,
            alert_level: None,
            alert_desc: None,
            ..Default::default()
        },
        TlsSession {
            flow_id: format!("{}:51005-{}:8443", VICTIM, INTRA_B),
            sni: Some("printer.corp".into()),
            cipher_suite: Some(0x0004), // RC4-MD5 (WEAK)
            tls_version: Some("TLS 1.1".into()),
            ja3: Some("b32309a26951912be7dba376398abc3b".into()),
            ja3s: None,
            cert_cn: Some("HP LaserJet Pro".into()),
            cert_san: vec![],
            cert_issuer: Some("self-signed".into()),
            cert_not_after: Some("2018-12-31".into()), // expired 2018
            first_seen: 6.0,
            alert_level: Some(2), // fatal alert
            alert_desc: Some(42), // bad_certificate
            ..Default::default()
        },
    ]
}

/// Security engine seed data — IDS alerts, OS guesses, ARP anomalies, brute force,
/// HTTP records, TLS weaknesses, DNS tunnel suspects, vuln hits.
pub fn security_seed() -> ScenarioSecurityData {
    use crate::net::security::*;
    ScenarioSecurityData {
        ids_alerts: vec![
            IdsAlert {
                pkt_no: 3,
                signature: "ET SCAN Nmap SYN Scan",
                severity: Severity::Medium,
                detail: "SYN scan from 192.168.1.50 → multiple ports".into(),
            },
            IdsAlert {
                pkt_no: 8,
                signature: "ET WEB_SERVER SQL Injection Attempt",
                severity: Severity::High,
                detail: "POST /admin/login — possible SQLi in auth field".into(),
            },
            IdsAlert {
                pkt_no: 19,
                signature: "ET MALWARE Cobalt Strike Beacon",
                severity: Severity::Critical,
                detail: "C2 beacon pattern — 64-byte PSH/ACK to 203.0.113.7:4444".into(),
            },
            IdsAlert {
                pkt_no: 41,
                signature: "ET POLICY Weak TLS Cipher RC4",
                severity: Severity::High,
                detail: "RC4-SHA negotiated to 203.0.113.7".into(),
            },
            IdsAlert {
                pkt_no: 48,
                signature: "ET EXPLOIT MS17-010 EternalBlue",
                severity: Severity::Critical,
                detail: "SMB buffer overflow pattern to 192.168.1.20:445".into(),
            },
            IdsAlert {
                pkt_no: 50,
                signature: "ET SCAN Kerberos AS-REQ Spray",
                severity: Severity::High,
                detail: "5 AS-REQ to different accounts within 0.5s".into(),
            },
            IdsAlert {
                pkt_no: 57,
                signature: "ET LATERAL SMB Admin Share Access",
                severity: Severity::High,
                detail: "TreeConnect to \\intranet\\C$ by non-admin user".into(),
            },
            IdsAlert {
                pkt_no: 62,
                signature: "ET EXFIL DNS Tunnel Suspected",
                severity: Severity::Medium,
                detail: "High-entropy subdomain queries to evil-tunnel.com".into(),
            },
        ],
        arp_anomalies: vec![
            ArpAnomaly {
                pkt_no: 1,
                ip: GATEWAY.into(),
                old_mac: "00:11:22:33:44:55".into(),
                new_mac: "de:ad:be:ef:00:01".into(),
            },
            ArpAnomaly {
                pkt_no: 2,
                ip: INTRA_A.into(),
                old_mac: "aa:bb:cc:dd:ee:ff".into(),
                new_mac: "de:ad:be:ef:00:02".into(),
            },
        ],
        os_guesses: vec![
            OsGuess {
                src_ip: VICTIM.into(),
                os: "Windows 10 (TTL=128)",
                ttl: 128,
                window: 65535,
            },
            OsGuess {
                src_ip: C2.into(),
                os: "Linux 4.x (TTL=64)",
                ttl: 64,
                window: 29200,
            },
            OsGuess {
                src_ip: INTRA_A.into(),
                os: "Linux 5.x (TTL=64)",
                ttl: 64,
                window: 65160,
            },
            OsGuess {
                src_ip: INTRA_B.into(),
                os: "Embedded/IoT (TTL=64)",
                ttl: 64,
                window: 4096,
            },
        ],
        vuln_hits: vec![
            VulnHit {
                pkt_no: 48,
                kind: "EternalBlue (MS17-010)",
                detail: "SMBv1 exploit pattern — TRANS2 SESSION_SETUP overwrite".into(),
            },
            VulnHit {
                pkt_no: 41,
                kind: "POODLE / SSL3 Fallback",
                detail: "TLS 1.0 negotiated with RC4 — susceptible to BEAST/POODLE".into(),
            },
            VulnHit {
                pkt_no: 8,
                kind: "Cleartext Authentication",
                detail: "HTTP Basic Auth credential sent unencrypted (port 80)".into(),
            },
            VulnHit {
                pkt_no: 13,
                kind: "FTP Cleartext Credential",
                detail: "FTP PASS command visible in cleartext on port 21".into(),
            },
        ],
        brute_force: vec![
            BruteForceAlert {
                src_ip: VICTIM.into(),
                dst_ip: INTRA_A.into(),
                port: 88,
                attempts: 5,
                service: "Kerberos",
            },
            BruteForceAlert {
                src_ip: VICTIM.into(),
                dst_ip: INTRA_A.into(),
                port: 80,
                attempts: 12,
                service: "HTTP",
            },
            BruteForceAlert {
                src_ip: "10.10.1.99".into(),
                dst_ip: VICTIM.into(),
                port: 22,
                attempts: 47,
                service: "SSH",
            },
            BruteForceAlert {
                src_ip: "10.10.1.99".into(),
                dst_ip: VICTIM.into(),
                port: 3389,
                attempts: 23,
                service: "RDP",
            },
        ],
        http_records: vec![
            HttpRecord {
                pkt_no: 8,
                src_ip: VICTIM.into(),
                dst_ip: INTRA_A.into(),
                port: 80,
                method: "POST".into(),
                path: "/admin/login".into(),
                user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".into(),
                response_code: Some(200),
            },
            HttpRecord {
                pkt_no: 10,
                src_ip: VICTIM.into(),
                dst_ip: INTRA_A.into(),
                port: 80,
                method: "GET".into(),
                path: "/api/v1/users".into(),
                user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".into(),
                response_code: Some(200),
            },
            HttpRecord {
                pkt_no: 15,
                src_ip: "10.10.1.99".into(),
                dst_ip: VICTIM.into(),
                port: 80,
                method: "GET".into(),
                path: "/.env".into(),
                user_agent: "python-requests/2.28.0".into(),
                response_code: Some(200),
            },
            HttpRecord {
                pkt_no: 16,
                src_ip: "10.10.1.99".into(),
                dst_ip: VICTIM.into(),
                port: 80,
                method: "GET".into(),
                path: "/wp-admin/".into(),
                user_agent: "Nikto/2.1.6".into(),
                response_code: Some(302),
            },
            HttpRecord {
                pkt_no: 17,
                src_ip: "10.10.1.99".into(),
                dst_ip: VICTIM.into(),
                port: 80,
                method: "GET".into(),
                path: "/etc/passwd".into(),
                user_agent: "curl/7.85.0".into(),
                response_code: Some(403),
            },
        ],
        tls_weaknesses: vec![
            TlsWeakness {
                pkt_no: 41,
                src_ip: VICTIM.into(),
                dst_ip: C2.into(),
                kind: "Weak Cipher",
                detail: "RC4-SHA negotiated — broken stream cipher, no forward secrecy".into(),
            },
            TlsWeakness {
                pkt_no: 42,
                src_ip: VICTIM.into(),
                dst_ip: INTRA_A.into(),
                kind: "Weak Cipher + Old Version",
                detail: "3DES-CBC-SHA on TLS 1.0 — SWEET32 vulnerable, BEAST attack surface".into(),
            },
            TlsWeakness {
                pkt_no: 43,
                src_ip: VICTIM.into(),
                dst_ip: INTRA_B.into(),
                kind: "Self-Signed + Expired Certificate",
                detail: "cert CN=HP LaserJet Pro expired 2018-12-31, issuer=self-signed".into(),
            },
            TlsWeakness {
                pkt_no: 44,
                src_ip: VICTIM.into(),
                dst_ip: C2.into(),
                kind: "Self-Signed Certificate",
                detail: "cert CN=evil-tunnel.com issued by self — no chain of trust".into(),
            },
        ],
        dns_suspects: vec![
            DnsTunnelSuspect {
                apex: "evil-tunnel.com".into(),
                query_count: 127,
                max_entropy: 4.87,
                max_subdomain_len: 52,
                unique_subdomains: 89,
                score: 18.4,
            },
            DnsTunnelSuspect {
                apex: "dnscat2.attacker.net".into(),
                query_count: 34,
                max_entropy: 4.62,
                max_subdomain_len: 63,
                unique_subdomains: 31,
                score: 12.7,
            },
        ],
    }
}

/// Credential hits to pre-seed.
pub fn credentials() -> Vec<crate::net::inspector::CredentialHit> {
    use crate::net::inspector::CredentialHit;
    vec![
        CredentialHit {
            proto: "HTTP".into(),
            kind: "HTTP-BasicAuth",
            value: "admin:pass123 (base64: YWRtaW46cGFzczEyMw==)".into(),
            pkt_no: 8,
        },
        CredentialHit {
            proto: "FTP".into(),
            kind: "FTP-USER",
            value: "administrator".into(),
            pkt_no: 12,
        },
        CredentialHit {
            proto: "FTP".into(),
            kind: "FTP-PASS",
            value: "Password123!".into(),
            pkt_no: 13,
        },
        CredentialHit {
            proto: "HTTP".into(),
            kind: "HTTP-BasicAuth",
            value: "backup_svc:BackupPass2023! (base64: YmFja3VwX3N2YzpCYWNrdXBQYXNzMjAyMyE=)"
                .into(),
            pkt_no: 17,
        },
        CredentialHit {
            proto: "SMTP".into(),
            kind: "SMTP-AUTH",
            value: "mailuser:SecretMail99".into(),
            pkt_no: 67,
        },
        CredentialHit {
            proto: "IMAP".into(),
            kind: "IMAP-LOGIN",
            value: "john.smith:Welcome1234".into(),
            pkt_no: 68,
        },
    ]
}
