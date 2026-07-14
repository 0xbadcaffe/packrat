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

fn ipv4_tcp_packet(no: u64, sequence: u32, flags: u8, payload: &[u8]) -> Packet {
    let mut bytes = vec![0_u8; 14 + 20 + 20];
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    bytes[23] = 6;
    bytes[26..30].copy_from_slice(&[203, 0, 113, 9]);
    bytes[30..34].copy_from_slice(&[10, 0, 0, 5]);
    bytes[34..36].copy_from_slice(&50000_u16.to_be_bytes());
    bytes[36..38].copy_from_slice(&443_u16.to_be_bytes());
    bytes[38..42].copy_from_slice(&sequence.to_be_bytes());
    bytes[46] = 0x50;
    bytes[47] = flags;
    bytes.extend_from_slice(payload);
    packet("TLS", 443, "", bytes).with_number_and_timestamp(no, no as f64)
}

#[test]
fn detects_conflicting_tcp_retransmission_but_allows_identical_retransmission() {
    let mut security = SecurityEngine::default();
    security.update(&ipv4_tcp_packet(1, 100, 0x18, b"original"));
    security.update(&ipv4_tcp_packet(2, 100, 0x18, b"original"));
    assert!(!security.ids_alerts.iter().any(|alert| {
        alert.signature == "Conflicting TCP retransmission"
    }));

    security.update(&ipv4_tcp_packet(3, 104, 0x18, b"CHANGED"));
    assert!(security.ids_alerts.iter().any(|alert| {
        alert.signature == "Conflicting TCP retransmission"
            && alert.severity == packrat_tui::net::security::Severity::Critical
    }));
}

#[test]
fn detects_illegal_and_malformed_tcp_headers() {
    let mut security = SecurityEngine::default();
    security.update(&ipv4_tcp_packet(1, 100, 0x03, b""));

    let mut malformed = ipv4_tcp_packet(2, 100, 0x10, b"");
    malformed.bytes[46] = 0x40;
    security.update(&malformed);

    assert!(security.ids_alerts.iter().any(|alert| alert.signature == "Illegal TCP flag combination"));
    assert!(security.ids_alerts.iter().any(|alert| alert.signature == "Malformed TCP header"));
}

#[test]
fn detects_tcp_payload_continuing_after_reset() {
    let mut security = SecurityEngine::default();
    security.update(&ipv4_tcp_packet(1, 100, 0x04, b""));
    security.update(&ipv4_tcp_packet(2, 101, 0x18, b"unexpected"));

    assert!(security.ids_alerts.iter().any(|alert| alert.signature == "TCP payload after reset"));
}

fn tcp_probe(no: u64, destination: [u8; 4], destination_port: u16, flags: u8, timestamp: f64) -> Packet {
    let mut probe = ipv4_tcp_packet(no, no as u32, flags, b"");
    probe.bytes[30..34].copy_from_slice(&destination);
    probe.bytes[36..38].copy_from_slice(&destination_port.to_be_bytes());
    probe.dst = destination.iter().map(u8::to_string).collect::<Vec<_>>().join(".");
    probe.dst_port = Some(destination_port);
    probe.timestamp = timestamp;
    probe
}

#[test]
fn detects_vertical_and_horizontal_scan_windows() {
    let mut vertical = SecurityEngine::default();
    for index in 0..12_u16 {
        vertical.update(&tcp_probe(index as u64 + 1, [10, 0, 0, 5], 1000 + index, 0x02, index as f64));
    }
    assert!(vertical.ids_alerts.iter().any(|alert| alert.signature == "Vertical port scan"));

    let mut horizontal = SecurityEngine::default();
    for index in 1..=12_u8 {
        horizontal.update(&tcp_probe(index as u64, [10, 0, 0, index], 445, 0x02, index as f64));
    }
    assert!(horizontal.ids_alerts.iter().any(|alert| alert.signature == "Horizontal host scan"));
}

#[test]
fn detects_tcp_stealth_scan_flag_patterns() {
    let mut security = SecurityEngine::default();
    security.update(&tcp_probe(1, [10, 0, 0, 5], 80, 0x00, 1.0));
    security.update(&tcp_probe(2, [10, 0, 0, 5], 80, 0x01, 2.0));
    security.update(&tcp_probe(3, [10, 0, 0, 5], 80, 0x29, 3.0));

    let count = security.ids_alerts.iter()
        .filter(|alert| alert.signature == "TCP stealth scan probe")
        .count();
    assert_eq!(count, 3);
}

#[test]
fn detects_syn_flood_within_one_second() {
    let mut security = SecurityEngine::default();
    for index in 0..100_u64 {
        security.update(&tcp_probe(index + 1, [10, 0, 0, 5], 443, 0x02, index as f64 / 1000.0));
    }

    assert!(security.ids_alerts.iter().any(|alert| {
        alert.signature == "SYN flood"
            && alert.severity == packrat_tui::net::security::Severity::Critical
    }));
}

#[test]
fn detects_icmp_address_sweep() {
    let mut security = SecurityEngine::default();
    for index in 1..=12_u8 {
        let mut echo = packet("ICMP", 0, "Echo request", vec![]);
        echo.no = index as u64;
        echo.timestamp = index as f64;
        echo.dst = format!("10.0.0.{index}");
        echo.dst_port = None;
        security.update(&echo);
    }

    assert!(security.ids_alerts.iter().any(|alert| alert.signature == "ICMP address sweep"));
}

fn ipv6_control_packet(no: u64, source_mac: [u8; 6], source: [u8; 16], hop_limit: u8, icmp: &[u8]) -> Packet {
    let mut bytes = vec![0_u8; 14 + 40];
    bytes[..6].copy_from_slice(&[0x33, 0x33, 0, 0, 0, 1]);
    bytes[6..12].copy_from_slice(&source_mac);
    bytes[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
    bytes[14] = 0x60;
    bytes[18..20].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
    bytes[20] = 58;
    bytes[21] = hop_limit;
    bytes[22..38].copy_from_slice(&source);
    bytes[38..54].copy_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    bytes.extend_from_slice(icmp);
    packet("ICMPv6", 0, "", bytes).with_number_and_timestamp(no, no as f64)
}

fn neighbor_advertisement(target: [u8; 16], mac: [u8; 6]) -> Vec<u8> {
    let mut icmp = vec![0_u8; 32];
    icmp[0] = 136;
    icmp[8..24].copy_from_slice(&target);
    icmp[24] = 2;
    icmp[25] = 1;
    icmp[26..32].copy_from_slice(&mac);
    icmp
}

#[test]
fn detects_invalid_ipv6_neighbor_discovery_and_binding_change() {
    let target = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
    let source = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut security = SecurityEngine::default();
    security.update(&ipv6_control_packet(1, [0, 1, 2, 3, 4, 5], source, 64, &neighbor_advertisement(target, [0, 1, 2, 3, 4, 5])));
    security.update(&ipv6_control_packet(2, [0, 1, 2, 3, 4, 6], source, 255, &neighbor_advertisement(target, [0, 1, 2, 3, 4, 6])));

    assert!(security.ids_alerts.iter().any(|alert| alert.signature == "Invalid IPv6 neighbor discovery hop limit"));
    assert!(security.ids_alerts.iter().any(|alert| alert.signature == "IPv6 neighbor binding changed"));
}

#[test]
fn detects_invalid_and_flooded_router_advertisements() {
    let global_source = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut ra = vec![0_u8; 16];
    ra[0] = 134;
    let mut security = SecurityEngine::default();
    for index in 0..20_u64 {
        let mut packet = ipv6_control_packet(index + 1, [0, 1, 2, 3, 4, 5], global_source, 255, &ra);
        packet.timestamp = index as f64 / 1000.0;
        security.update(&packet);
    }

    assert!(security.ids_alerts.iter().any(|alert| alert.signature == "Invalid IPv6 router advertisement source"));
    assert!(security.ids_alerts.iter().any(|alert| alert.signature == "IPv6 router advertisement flood"));
}

#[test]
fn detects_excessive_ipv6_extension_header_chain() {
    let source = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut extensions = vec![0_u8; 9 * 8 + 8];
    for index in 0..9 {
        extensions[index * 8] = if index == 8 { 58 } else { 0 };
    }
    extensions[9 * 8] = 128;
    let mut packet = ipv6_control_packet(1, [0, 1, 2, 3, 4, 5], source, 255, &extensions);
    packet.bytes[20] = 0;

    let mut security = SecurityEngine::default();
    security.update(&packet);
    assert!(security.ids_alerts.iter().any(|alert| alert.signature == "Excessive IPv6 extension headers"));
}

fn lldp_packet(no: u64, source_mac: [u8; 6], chassis: &[u8]) -> Packet {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);
    bytes.extend_from_slice(&source_mac);
    bytes.extend_from_slice(&0x88cc_u16.to_be_bytes());
    let value_len = chassis.len() + 1;
    bytes.extend_from_slice(&(((1_u16) << 9) | value_len as u16).to_be_bytes());
    bytes.push(7);
    bytes.extend_from_slice(chassis);
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    packet("LLDP", 0, "", bytes).with_number_and_timestamp(no, no as f64)
}

#[test]
fn detects_stp_topology_change_and_lldp_identity_change() {
    let mut security = SecurityEngine::default();
    let mut bpdu = vec![0_u8; 22];
    bpdu[..6].copy_from_slice(&[0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]);
    bpdu[6..12].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
    bpdu[14..17].copy_from_slice(&[0x42, 0x42, 0x03]);
    bpdu[20] = 0x80;
    security.update(&packet("STP", 0, "", bpdu));
    security.update(&lldp_packet(2, [0, 1, 2, 3, 4, 5], b"switch-a"));
    security.update(&lldp_packet(3, [0, 1, 2, 3, 4, 5], b"switch-b"));

    assert!(security.ids_alerts.iter().any(|alert| alert.signature == "STP topology change"));
    assert!(security.ids_alerts.iter().any(|alert| alert.signature == "LLDP chassis identity changed"));
}

fn behavior_packet(no: u64, timestamp: f64, length: usize, bytes: Vec<u8>) -> Packet {
    let mut packet = packet("TLS", 443, "", bytes);
    packet.no = no;
    packet.timestamp = timestamp;
    packet.src = "10.0.0.5".into();
    packet.dst = "8.8.8.8".into();
    packet.src_port = Some(50000);
    packet.dst_port = Some(443);
    packet.length = length as u16;
    packet
}

#[test]
fn detects_periodic_fixed_size_command_and_control_beacon() {
    let mut security = SecurityEngine::default();
    for index in 0..7_u64 {
        security.update(&behavior_packet(index + 1, index as f64 * 10.0, 120, vec![0; 120]));
    }
    assert!(security.ids_alerts.iter().any(|alert| {
        alert.signature == "Periodic command-and-control beacon"
    }));

    let mut irregular = SecurityEngine::default();
    for (index, timestamp) in [0.0, 2.0, 9.0, 11.0, 27.0, 31.0, 60.0].into_iter().enumerate() {
        irregular.update(&behavior_packet(index as u64 + 1, timestamp, 100 + index * 17, vec![0; 100]));
    }
    assert!(!irregular.ids_alerts.iter().any(|alert| {
        alert.signature == "Periodic command-and-control beacon"
    }));
}

#[test]
fn detects_large_high_entropy_outbound_transfer() {
    let mut security = SecurityEngine::default();
    let encrypted_like = (0..60_000).map(|index| ((index * 73) % 256) as u8).collect::<Vec<_>>();
    for index in 0..17_u64 {
        security.update(&behavior_packet(index + 1, index as f64 / 10.0, 60_000, encrypted_like.clone()));
    }

    assert!(security.ids_alerts.iter().any(|alert| alert.signature == "Large asymmetric outbound transfer"));
    assert!(security.ids_alerts.iter().any(|alert| alert.signature == "High-entropy outbound transfer"));
}
