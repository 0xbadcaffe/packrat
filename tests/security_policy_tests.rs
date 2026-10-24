//! Replay fixtures for Packrat's shipped passive IDS signatures.

use packrat_tui::analysis::vlan::{AlertSeverity, VlanIntel};
use packrat_tui::net::packet::Packet;
use packrat_tui::net::security::SecurityEngine;
use rstest::rstest;

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
        "EternalBlue" => packet("SMB", 445, "", b"prefixSMBrsuffix".to_vec()),
        "BlueKeep (CVE-2019-0708)" => {
            let mut bytes = vec![0_u8; 120];
            bytes[..3].copy_from_slice(&[0x03, 0x00, 0x00]);
            packet("RDP", 3389, "", bytes)
        }
        "Log4Shell (CVE-2021-44228)" => {
            packet("HTTP", 8080, "", b"${jndi:ldap://example.test/x}".to_vec())
        }
        "Shellcode NOP sled" => packet("TCP", 4444, "", vec![0x90; 20]),
        "LLMNR Poisoning" => packet("UDP", 5355, "", vec![0; 20]),
        "NBNS WPAD Poisoning" => packet("NBNS", 137, "", vec![0x00, 0x20, 0x43, 0x4b]),
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
        "PrintNightmare (CVE-2021-1675)" => packet("SMB", 445, "", b"\x1c\x00SpoolSS".to_vec()),
        "Pass-the-Hash (suspected)" => packet("SMB", 445, "", b"NTLMSSP authentication".to_vec()),
        "Log4Shell via DNS (CVE-2021-44228)" => {
            packet("DNS", 53, "query jndi callback", vec![0; 20])
        }
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
    let server_message = matches!(message_type, 2 | 5);
    let mut bootp = vec![0_u8; 240];
    bootp[0] = if server_message { 2 } else { 1 };
    bootp[1] = 1;
    bootp[2] = 6;
    bootp[28..34].copy_from_slice(&client_mac);
    bootp[236..240].copy_from_slice(&[99, 130, 83, 99]);
    bootp.extend_from_slice(&[53, 1, message_type]);
    if let Some(server) = server_id {
        bootp.extend_from_slice(&[54, 4]);
        bootp.extend_from_slice(&server);
    }
    bootp.push(255);

    let udp_len = 8 + bootp.len();
    let mut bytes = vec![0_u8; 14 + 20 + 8];
    bytes[..6].copy_from_slice(&[0xff; 6]);
    bytes[6..12].copy_from_slice(&source_mac);
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&((20 + udp_len) as u16).to_be_bytes());
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(if server_message {
        &[10, 0, 0, 1]
    } else {
        &[0, 0, 0, 0]
    });
    bytes[30..34].copy_from_slice(&[255, 255, 255, 255]);
    let (source_port, destination_port) = if server_message {
        (67_u16, 68_u16)
    } else {
        (68, 67)
    };
    bytes[34..36].copy_from_slice(&source_port.to_be_bytes());
    bytes[36..38].copy_from_slice(&destination_port.to_be_bytes());
    bytes[38..40].copy_from_slice(&(udp_len as u16).to_be_bytes());
    bytes.extend_from_slice(&bootp);

    let mut packet = packet("DHCP", destination_port, "", bytes)
        .with_number_and_timestamp(no, no as f64 / 100.0);
    packet.src = if server_message {
        "10.0.0.1".into()
    } else {
        "0.0.0.0".into()
    };
    packet.dst = "255.255.255.255".into();
    packet.src_port = Some(source_port);
    packet.dst_port = Some(destination_port);
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
