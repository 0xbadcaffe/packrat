//! Replay fixtures for Packrat's shipped passive IDS signatures.

use packrat_tui::analysis::vlan::{AlertSeverity, VlanIntel};
use packrat_tui::net::packet::Packet;
use packrat_tui::net::security::SecurityEngine;
use rstest::rstest;

#[path = "support/dtp.rs"]
mod dtp;
#[path = "support/dhcp.rs"]
mod dhcp_fixture;

fn packet(protocol: &str, destination_port: u16, info: &str, bytes: Vec<u8>) -> Packet {
    Packet {
        capture: None,
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
        "Log4Shell (CVE-2021-44228)" => {
            ipv4_tcp_packet(1, 100, 0x18, b"${jndi:ldap://example.test/x}")
        }
        "Repeated NOP-like byte pattern" => ipv4_tcp_packet(1, 100, 0x18, &[0x90; 20]),
        "Directory Traversal" => packet("HTTP", 80, "", b"../../../../../../etc/passwd".to_vec()),
        "SQL Injection Probe" => {
            packet("HTTP", 80, "", b"UNION SELECT password FROM users".to_vec())
        }
        "XSS Probe" => packet("HTTP", 80, "", b"<script>alert(1)</script>".to_vec()),
        "Heartbleed (CVE-2014-0160)" => packet(
            "TLS",
            443,
            "",
            vec![0x18, 0x03, 0x02, 0xff, 0xff, 0x01, 0x00],
        ),
        _ => panic!("unknown fixture {name}"),
    }
}

fn ethernet_packet(no: u64, src_mac: [u8; 6], dst_mac: [u8; 6], vlan_id: Option<u16>) -> Packet {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&dst_mac);
    bytes.extend_from_slice(&src_mac);
    bytes.extend_from_slice(&[0x08, 0x00]);
    Packet {
        capture: None,
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

fn tcp_probe(
    no: u64,
    destination: [u8; 4],
    destination_port: u16,
    flags: u8,
    timestamp: f64,
) -> Packet {
    let mut probe = ipv4_tcp_packet(no, no as u32, flags, b"");
    probe.bytes[30..34].copy_from_slice(&destination);
    probe.bytes[36..38].copy_from_slice(&destination_port.to_be_bytes());
    probe.dst = destination
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(".");
    probe.dst_port = Some(destination_port);
    probe.timestamp = timestamp;
    probe
}

fn ipv6_control_packet(
    no: u64,
    source_mac: [u8; 6],
    source: [u8; 16],
    hop_limit: u8,
    icmp: &[u8],
) -> Packet {
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

fn checked_router_advertisement(no: u64, mac: [u8; 6], source: [u8; 16], hop_limit: u8, icmp: &[u8]) -> Packet {
    let mut packet = ipv6_control_packet(no, mac, source, hop_limit, icmp);
    assert_eq!(&icmp[2..4], &[0, 0]);
    let mut sum = packet.bytes[22..54].chunks(2).chain(icmp.chunks(2))
        .map(|word| u32::from(u16::from_be_bytes([word[0], word.get(1).copied().unwrap_or(0)])))
        .sum::<u32>() + icmp.len() as u32 + 58;
    while sum > 0xffff { sum = (sum >> 16) + (sum & 0xffff); }
    packet.bytes[56..58].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet
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

fn lldp_packet(no: u64, source_mac: [u8; 6], chassis: &[u8]) -> Packet {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);
    bytes.extend_from_slice(&source_mac);
    bytes.extend_from_slice(&0x88cc_u16.to_be_bytes());
    let value_len = chassis.len() + 1;
    bytes.extend_from_slice(&(((1_u16) << 9) | value_len as u16).to_be_bytes());
    bytes.push(7);
    bytes.extend_from_slice(chassis);
    bytes.extend_from_slice(&[0x04, 2, 7, 1]); // Port ID TLV, locally assigned.
    bytes.extend_from_slice(&[0x06, 2, 0, 30]); // TTL TLV.
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    packet("LLDP", 0, "", bytes).with_number_and_timestamp(no, no as f64)
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

fn dhcp_packet(
    no: u64,
    message_type: u8,
    source_mac: [u8; 6],
    client_mac: [u8; 6],
    server_id: Option<[u8; 4]>,
) -> Packet {
    let mut packet = dhcp_fixture::dhcp_packet(no, message_type, source_mac, client_mac, server_id);
    packet.vlan_id = Some(20);
    packet
}

fn http_packet(no: u64, sequence: u32, payload: &[u8]) -> Packet {
    let mut packet = ipv4_tcp_packet(no, sequence, 0x18, payload);
    packet.bytes[36..38].copy_from_slice(&80_u16.to_be_bytes());
    packet.protocol = "HTTP".into();
    packet.dst_port = Some(80);
    packet
}

#[path = "security_policy/cases_1.rs"]
mod cases_1;
#[path = "security_policy/cases_2.rs"]
mod cases_2;
#[path = "security_policy/outbound_entropy_cases.rs"]
mod outbound_entropy_cases;
#[path = "security_policy/cases_3.rs"]
mod cases_3;
#[path = "security_policy/auth_transport_cases.rs"]
mod auth_transport_cases;
#[path = "security_policy/dhcp_cases.rs"]
mod dhcp_cases;
#[path = "security_policy/lookup_marker_cases.rs"]
mod lookup_marker_cases;
#[path = "security_policy/tcp_reset_cases.rs"]
mod tcp_reset_cases;
#[path = "security_policy/smb_anonymous_cases.rs"]
mod smb_anonymous_cases;
#[path = "security_policy/tls_selection_cases.rs"]
mod tls_selection_cases;
#[path = "security_policy/http_exposure_cases.rs"]
mod http_exposure_cases;
#[path = "security_policy/ftp_control_cases.rs"]
mod ftp_control_cases;
#[path = "security_policy/telnet_prompt_cases.rs"]
mod telnet_prompt_cases;
#[path = "security_policy/ndp_binding_cases.rs"]
mod ndp_binding_cases;
#[path = "security_policy/lldp_identity_cases.rs"]
mod lldp_identity_cases;
#[path = "security_policy/stp_indication_cases.rs"]
mod stp_indication_cases;
#[path = "security_policy/ndp_hop_limit_cases.rs"]
mod ndp_hop_limit_cases;
#[path = "security_policy/ipv6_extension_cases.rs"]
mod ipv6_extension_cases;
#[path = "security_policy/payload_byte_run_cases.rs"]
mod payload_byte_run_cases;
#[path = "security_policy/http_observation_cases.rs"]
mod http_observation_cases;
#[path = "security_policy/ipv4_fragment_volume_cases.rs"]
mod ipv4_fragment_volume_cases;
#[path = "security_policy/ipv4_discovery_cases.rs"]
mod ipv4_discovery_cases;
#[path = "security_policy/link_scope_cases.rs"]
mod link_scope_cases;
