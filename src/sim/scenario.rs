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

    pkts
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
