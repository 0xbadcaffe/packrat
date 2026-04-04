/// Raw byte parser: Ethernet → VLAN → IPv4/v6 → transport protocols.
use crate::net::packet::Packet;

/// Parse a raw Ethernet frame into a `Packet`.
pub fn parse_ethernet(data: &[u8], no: u64, ts: f64) -> Packet {
    if data.len() < 14 {
        return unknown(data, no, ts);
    }

    let mut offset = 12usize; // position of EtherType field
    let mut vlan_id: Option<u16> = None;

    // Strip 802.1Q VLAN tag(s)
    loop {
        if offset + 2 > data.len() {
            return unknown(data, no, ts);
        }
        let etype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        if etype == 0x8100 || etype == 0x88a8 {
            // 4-byte tag: TCI (2 bytes) + inner EtherType (2 bytes)
            if offset + 4 > data.len() {
                return unknown(data, no, ts);
            }
            let tci = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            vlan_id = Some(tci & 0x0FFF); // 12-bit VLAN ID
            offset += 4;
        } else {
            break;
        }
    }

    let ether_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let payload = &data[offset + 2..];

    match ether_type {
        0x0806 => parse_arp(payload, data, no, ts, vlan_id),
        0x0800 => parse_ipv4(payload, data, no, ts, vlan_id),
        0x86DD => parse_ipv6(payload, data, no, ts, vlan_id),
        0x8847 | 0x8848 => parse_mpls(payload, data, no, ts, vlan_id),
        0x8863 => parse_pppoe(payload, data, no, ts, vlan_id, "discovery"),
        0x8864 => parse_pppoe(payload, data, no, ts, vlan_id, "session"),
        _ => unknown(data, no, ts),
    }
}

fn parse_arp(payload: &[u8], raw: &[u8], no: u64, ts: f64, vlan_id: Option<u16>) -> Packet {
    if payload.len() < 28 {
        return unknown(raw, no, ts);
    }
    let src = fmt_ip(&payload[14..18]);
    let dst = fmt_ip(&payload[24..28]);
    let opcode = u16::from_be_bytes([payload[6], payload[7]]);
    let op_str = if opcode == 1 { "request" } else { "reply" };
    Packet {
        no,
        timestamp: ts,
        src: src.clone(),
        dst: dst.clone(),
        protocol: "ARP".into(),
        length: raw.len() as u16,
        info: format!("Who has {}? Tell {} ({})", dst, src, op_str),
        src_port: None,
        dst_port: None,
        vlan_id,
        bytes: raw.to_vec(),
    }
}

fn parse_ipv4(payload: &[u8], raw: &[u8], no: u64, ts: f64, vlan_id: Option<u16>) -> Packet {
    if payload.len() < 20 {
        return unknown(raw, no, ts);
    }
    let ihl = ((payload[0] & 0x0F) as usize) * 4;
    let proto_num = payload[9];
    let src_ip = fmt_ip(&payload[12..16]);
    let dst_ip = fmt_ip(&payload[16..20]);

    if payload.len() < ihl {
        return unknown(raw, no, ts);
    }
    let transport = &payload[ihl..];

    parse_transport(transport, raw, no, ts, proto_num, src_ip, dst_ip, vlan_id)
}

fn parse_ipv6(payload: &[u8], raw: &[u8], no: u64, ts: f64, vlan_id: Option<u16>) -> Packet {
    if payload.len() < 40 {
        return unknown(raw, no, ts);
    }
    let next_header = payload[6];
    let src_ip = fmt_ipv6(&payload[8..24]);
    let dst_ip = fmt_ipv6(&payload[24..40]);
    let transport = &payload[40..];

    parse_transport(transport, raw, no, ts, next_header, src_ip, dst_ip, vlan_id)
}

fn parse_transport(
    transport: &[u8],
    raw: &[u8],
    no: u64,
    ts: f64,
    proto_num: u8,
    src_ip: String,
    dst_ip: String,
    vlan_id: Option<u16>,
) -> Packet {
    match proto_num {
        1 => parse_icmp(transport, raw, no, ts, src_ip, dst_ip, vlan_id),
        2 => parse_igmp(transport, raw, no, ts, src_ip, dst_ip, vlan_id),
        6 => parse_tcp(transport, raw, no, ts, src_ip, dst_ip, vlan_id),
        17 => parse_udp(transport, raw, no, ts, src_ip, dst_ip, vlan_id),
        47 => parse_gre(transport, raw, no, ts, src_ip, dst_ip, vlan_id),
        50 => parse_esp(transport, raw, no, ts, src_ip, dst_ip, vlan_id),
        51 => parse_ah(transport, raw, no, ts, src_ip, dst_ip, vlan_id),
        58 => parse_icmpv6(transport, raw, no, ts, src_ip, dst_ip, vlan_id),
        112 => parse_vrrp(transport, raw, no, ts, src_ip, dst_ip, vlan_id),
        89  => parse_ospf(transport, raw, no, ts, src_ip, dst_ip, vlan_id),
        88  => parse_eigrp(transport, raw, no, ts, src_ip, dst_ip, vlan_id),
        103 => parse_pim(transport, raw, no, ts, src_ip, dst_ip, vlan_id),
        _ => Packet {
            no,
            timestamp: ts,
            src: src_ip,
            dst: dst_ip,
            protocol: format!("IP({})", proto_num),
            length: raw.len() as u16,
            info: "Unknown IP protocol".into(),
            src_port: None,
            dst_port: None,
            vlan_id,
            bytes: raw.to_vec(),
        },
    }
}

fn parse_icmp(
    t: &[u8], raw: &[u8], no: u64, ts: f64,
    src: String, dst: String, vlan_id: Option<u16>,
) -> Packet {
    let info = if t.len() >= 2 {
        match t[0] {
            0  => "Echo reply".into(),
            8  => "Echo request".into(),
            3  => "Destination unreachable".into(),
            11 => "Time exceeded".into(),
            _  => format!("ICMP type={}", t[0]),
        }
    } else {
        "ICMP".into()
    };
    Packet {
        no, timestamp: ts, src, dst,
        protocol: "ICMP".into(),
        length: raw.len() as u16,
        info, src_port: None, dst_port: None, vlan_id,
        bytes: raw.to_vec(),
    }
}

fn parse_icmpv6(
    t: &[u8], raw: &[u8], no: u64, ts: f64,
    src: String, dst: String, vlan_id: Option<u16>,
) -> Packet {
    let info = if t.len() >= 2 {
        match t[0] {
            128 => "Echo request".into(),
            129 => "Echo reply".into(),
            133 => "Router solicitation".into(),
            134 => "Router advertisement".into(),
            135 => "Neighbor solicitation".into(),
            136 => "Neighbor advertisement".into(),
            _   => format!("ICMPv6 type={}", t[0]),
        }
    } else {
        "ICMPv6".into()
    };
    Packet {
        no, timestamp: ts, src, dst,
        protocol: "ICMPv6".into(),
        length: raw.len() as u16,
        info, src_port: None, dst_port: None, vlan_id,
        bytes: raw.to_vec(),
    }
}

fn parse_tcp(
    t: &[u8], raw: &[u8], no: u64, ts: f64,
    src: String, dst: String, vlan_id: Option<u16>,
) -> Packet {
    if t.len() < 20 {
        return Packet {
            no, timestamp: ts, src, dst,
            protocol: "TCP".into(),
            length: raw.len() as u16,
            info: "TCP (truncated)".into(),
            src_port: None, dst_port: None, vlan_id,
            bytes: raw.to_vec(),
        };
    }
    let sp = u16::from_be_bytes([t[0], t[1]]);
    let dp = u16::from_be_bytes([t[2], t[3]]);
    let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
    let flags = t[13];
    let flag_str = fmt_tcp_flags(flags);

    let protocol = classify_tcp(sp, dp);
    let info = format!("{} → {} [{}] Seq={}", sp, dp, flag_str, seq);

    Packet {
        no, timestamp: ts, src, dst,
        protocol: protocol.into(),
        length: raw.len() as u16,
        info,
        src_port: Some(sp),
        dst_port: Some(dp),
        vlan_id,
        bytes: raw.to_vec(),
    }
}

fn parse_udp(
    t: &[u8], raw: &[u8], no: u64, ts: f64,
    src: String, dst: String, vlan_id: Option<u16>,
) -> Packet {
    if t.len() < 8 {
        return Packet {
            no, timestamp: ts, src, dst,
            protocol: "UDP".into(),
            length: raw.len() as u16,
            info: "UDP (truncated)".into(),
            src_port: None, dst_port: None, vlan_id,
            bytes: raw.to_vec(),
        };
    }
    let sp = u16::from_be_bytes([t[0], t[1]]);
    let dp = u16::from_be_bytes([t[2], t[3]]);
    let payload_len = (t.len() as u16).saturating_sub(8);

    let protocol = classify_udp(sp, dp);
    let protocol = if protocol == "UDP" && t.len() >= 12 && (t[8] >> 6) == 2 {
        "RTP"
    } else {
        protocol
    };
    let info = format!("{} → {} Len={}", sp, dp, payload_len);

    Packet {
        no, timestamp: ts, src, dst,
        protocol: protocol.into(),
        length: raw.len() as u16,
        info,
        src_port: Some(sp),
        dst_port: Some(dp),
        vlan_id,
        bytes: raw.to_vec(),
    }
}

fn classify_tcp(sp: u16, dp: u16) -> &'static str {
    match (sp, dp) {
        (_, 80) | (80, _) | (_, 8080) | (8080, _)  => "HTTP",
        (_, 443) | (443, _)                          => "HTTPS",
        (_, 22)  | (22, _)                           => "SSH",
        (_, 25)  | (25, _)                           => "SMTP",
        (_, 587) | (587, _)                          => "SMTP",
        (_, 143) | (143, _)                          => "IMAP",
        (_, 993) | (993, _)                          => "IMAPS",
        (_, 110) | (110, _)                          => "POP3",
        (_, 3306) | (3306, _)                        => "MySQL",
        (_, 5432) | (5432, _)                        => "PostgreSQL",
        (_, 6379) | (6379, _)                        => "Redis",
        (_, 27017) | (27017, _)                      => "MongoDB",
        (_, 9200) | (9200, _)                        => "Elasticsearch",
        // Industrial / OT protocols
        (_, 502)   | (502, _)                        => "Modbus",
        (_, 1883)  | (1883, _)                       => "MQTT",
        (_, 8883)  | (8883, _)                       => "MQTT-TLS",
        (_, 4840)  | (4840, _)                       => "OPC-UA",
        (_, 20000) | (20000, _)                      => "DNP3",
        (_, 44818) | (44818, _)                      => "EtherNet/IP",
        (_, 102)   | (102, _)                        => "S7comm",
        (_, 2404)  | (2404, _)                       => "IEC-104",
        (_, 20) | (20, _) | (_, 21) | (21, _)        => "FTP",
        (_, 23) | (23, _)                             => "Telnet",
        (_, 179) | (179, _)                           => "BGP",
        (_, 389) | (389, _)                           => "LDAP",
        (_, 5060) | (5060, _)                         => "SIP",
        (_, 5061) | (5061, _)                         => "SIPS",
        (_, 13400) | (13400, _)                       => "DoIP",
        (_, 30490) | (30490, _)                       => "SOME/IP",
        (_, 445)   | (445, _)                         => "SMB",
        (_, 3389)  | (3389, _)                        => "RDP",
        (_, 88)    | (88, _)                          => "Kerberos",
        (_, 139)   | (139, _)                         => "NetBIOS-SSN",
        (_, 554)   | (554, _)                         => "RTSP",
        (_, 9092)  | (9092, _)                        => "Kafka",
        (_, 5672)  | (5672, _)                        => "AMQP",
        (_, 4222)  | (4222, _)                        => "NATS",
        (_, 11211) | (11211, _)                       => "Memcached",
        (_, 5900)  | (5900, _)                        => "VNC",
        (_, 2375)  | (2375, _) | (_, 2376) | (2376, _) => "Docker",
        (_, 9090)  | (9090, _)                        => "Prometheus",
        (_, 2379)  | (2379, _) | (_, 2380) | (2380, _) => "etcd",
        _                                             => "TCP",
    }
}

fn classify_udp(sp: u16, dp: u16) -> &'static str {
    match (sp, dp) {
        (53, _) | (_, 53)       => "DNS",
        (5353, _) | (_, 5353)   => "mDNS",
        (67, _) | (_, 67) | (68, _) | (_, 68) => "DHCP",
        (123, _) | (_, 123)     => "NTP",
        (443, _) | (_, 443)     => "QUIC",
        (161, _) | (_, 161)     => "SNMP",
        (162, _) | (_, 162)     => "SNMP-trap",
        (514, _) | (_, 514)     => "Syslog",
        // Industrial / OT protocols
        (5683, _) | (_, 5683)   => "CoAP",
        (5684, _) | (_, 5684)   => "CoAP-DTLS",
        (47808, _) | (_, 47808) => "BACnet",
        (20000, _) | (_, 20000) => "DNP3",
        (2222, _) | (_, 2222)   => "EtherNet/IP",
        (319, _) | (_, 319) | (320, _) | (_, 320) => "PTP",
        (546, _) | (_, 546) | (547, _) | (_, 547) => "DHCPv6",
        (4789, _) | (_, 4789)                      => "VXLAN",
        (2152, _) | (_, 2152)                      => "GTP",
        (51820, _) | (_, 51820)                    => "WireGuard",
        (5060, _) | (_, 5060)                      => "SIP",
        (5061, _) | (_, 5061)                      => "SIPS",
        (1812, _) | (_, 1812) | (1813, _) | (_, 1813) | (1645, _) | (_, 1645) | (1646, _) | (_, 1646) => "Radius",
        (30490, _) | (_, 30490)                    => "SOME/IP",
        (9, _) | (_, 9)                            => "WoL",
        (137, _) | (_, 137)   => "NBNS",
        (69, _)  | (_, 69)    => "TFTP",
        (3478, _)| (_, 3478)  => "STUN",
        (1900, _)| (_, 1900)  => "SSDP",
        (520, _) | (_, 520)   => "RIP",
        (88, _)  | (_, 88)    => "Kerberos",
        _                       => "UDP",
    }
}

fn parse_igmp(t: &[u8], raw: &[u8], no: u64, ts: f64, src: String, dst: String, vlan_id: Option<u16>) -> Packet {
    let info = if t.len() >= 8 {
        let group = fmt_ip(&t[4..8]);
        match t[0] {
            0x11 => format!("Membership Query group={}", group),
            0x16 => format!("Membership Report v2 group={}", group),
            0x17 => format!("Leave Group {}", group),
            0x22 => "Membership Report v3".into(),
            _ => format!("IGMP type=0x{:02x}", t[0]),
        }
    } else { "IGMP".into() };
    Packet { no, timestamp: ts, src, dst, protocol: "IGMP".into(), length: raw.len() as u16, info, src_port: None, dst_port: None, vlan_id, bytes: raw.to_vec() }
}

fn parse_gre(t: &[u8], raw: &[u8], no: u64, ts: f64, src: String, dst: String, vlan_id: Option<u16>) -> Packet {
    let encap = if t.len() >= 4 {
        match u16::from_be_bytes([t[2], t[3]]) { 0x0800 => " (IPv4)", 0x86DD => " (IPv6)", _ => "" }
    } else { "" };
    Packet { no, timestamp: ts, src, dst, protocol: "GRE".into(), length: raw.len() as u16, info: format!("GRE Encapsulated{}", encap), src_port: None, dst_port: None, vlan_id, bytes: raw.to_vec() }
}

fn parse_esp(t: &[u8], raw: &[u8], no: u64, ts: f64, src: String, dst: String, vlan_id: Option<u16>) -> Packet {
    let spi = if t.len() >= 4 { format!("SPI=0x{:08x}", u32::from_be_bytes([t[0],t[1],t[2],t[3]])) } else { "SPI=?".into() };
    Packet { no, timestamp: ts, src, dst, protocol: "ESP".into(), length: raw.len() as u16, info: format!("IPSec ESP {}", spi), src_port: None, dst_port: None, vlan_id, bytes: raw.to_vec() }
}

fn parse_ah(t: &[u8], raw: &[u8], no: u64, ts: f64, src: String, dst: String, vlan_id: Option<u16>) -> Packet {
    let spi = if t.len() >= 8 { format!("SPI=0x{:08x}", u32::from_be_bytes([t[4],t[5],t[6],t[7]])) } else { "SPI=?".into() };
    Packet { no, timestamp: ts, src, dst, protocol: "AH".into(), length: raw.len() as u16, info: format!("IPSec AH {}", spi), src_port: None, dst_port: None, vlan_id, bytes: raw.to_vec() }
}

fn parse_vrrp(t: &[u8], raw: &[u8], no: u64, ts: f64, src: String, dst: String, vlan_id: Option<u16>) -> Packet {
    let info = if t.len() >= 4 {
        format!("VRRPv{} VRID={} Priority={}", t[0] >> 4, t[1], t[2])
    } else { "VRRP".into() };
    Packet { no, timestamp: ts, src, dst, protocol: "VRRP".into(), length: raw.len() as u16, info, src_port: None, dst_port: None, vlan_id, bytes: raw.to_vec() }
}

fn parse_mpls(payload: &[u8], raw: &[u8], no: u64, ts: f64, vlan_id: Option<u16>) -> Packet {
    let label = if payload.len() >= 4 {
        (u32::from_be_bytes([payload[0],payload[1],payload[2],payload[3]]) >> 12) & 0xFFFFF
    } else { 0 };
    Packet { no, timestamp: ts, src: "?.?.?.?".into(), dst: "?.?.?.?".into(), protocol: "MPLS".into(), length: raw.len() as u16, info: format!("MPLS Label={}", label), src_port: None, dst_port: None, vlan_id, bytes: raw.to_vec() }
}

fn parse_pppoe(payload: &[u8], raw: &[u8], no: u64, ts: f64, vlan_id: Option<u16>, kind: &str) -> Packet {
    let info = if kind == "session" {
        let sid = if payload.len() >= 4 { u16::from_be_bytes([payload[2], payload[3]]) } else { 0 };
        format!("PPPoE Session id=0x{:04x}", sid)
    } else {
        let code = payload.get(1).copied().unwrap_or(0);
        match code { 0x09=>"PPPoE PADI".into(), 0x07=>"PPPoE PADO".into(), 0x19=>"PPPoE PADR".into(), 0x65=>"PPPoE PADS".into(), 0xa7=>"PPPoE PADT".into(), _=>format!("PPPoE code=0x{:02x}",code) }
    };
    Packet { no, timestamp: ts, src: "?.?.?.?".into(), dst: "?.?.?.?".into(), protocol: "PPPoE".into(), length: raw.len() as u16, info, src_port: None, dst_port: None, vlan_id, bytes: raw.to_vec() }
}

fn parse_ospf(t: &[u8], raw: &[u8], no: u64, ts: f64, src: String, dst: String, vlan_id: Option<u16>) -> Packet {
    let msg = if t.len() >= 2 { match t[1] { 1=>"Hello", 2=>"DBD", 3=>"LSR", 4=>"LSU", 5=>"LSAck", _=>"Unknown" } } else { "OSPF" };
    Packet { no, timestamp: ts, src, dst, protocol: "OSPF".into(), length: raw.len() as u16, info: format!("OSPF {}", msg), src_port: None, dst_port: None, vlan_id, bytes: raw.to_vec() }
}

fn parse_eigrp(t: &[u8], raw: &[u8], no: u64, ts: f64, src: String, dst: String, vlan_id: Option<u16>) -> Packet {
    let op = t.get(1).copied().unwrap_or(0);
    Packet { no, timestamp: ts, src, dst, protocol: "EIGRP".into(), length: raw.len() as u16, info: format!("EIGRP opcode={}", op), src_port: None, dst_port: None, vlan_id, bytes: raw.to_vec() }
}

fn parse_pim(t: &[u8], raw: &[u8], no: u64, ts: f64, src: String, dst: String, vlan_id: Option<u16>) -> Packet {
    let types = ["Hello", "Register", "Register-Stop", "Join/Prune", "Bootstrap", "Assert", "Graft", "State-Refresh", "Candidate-RP"];
    let mt = (t.get(1).copied().unwrap_or(0) & 0x0F) as usize;
    let name = types.get(mt).copied().unwrap_or("Unknown");
    Packet { no, timestamp: ts, src, dst, protocol: "PIM".into(), length: raw.len() as u16, info: format!("PIM {}", name), src_port: None, dst_port: None, vlan_id, bytes: raw.to_vec() }
}

fn unknown(raw: &[u8], no: u64, ts: f64) -> Packet {
    Packet {
        no,
        timestamp: ts,
        src: "?.?.?.?".into(),
        dst: "?.?.?.?".into(),
        protocol: "RAW".into(),
        length: raw.len() as u16,
        info: "Unparseable frame".into(),
        src_port: None,
        dst_port: None,
        vlan_id: None,
        bytes: raw.to_vec(),
    }
}

fn fmt_ip(b: &[u8]) -> String {
    if b.len() < 4 { return "0.0.0.0".into(); }
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn fmt_ipv6(b: &[u8]) -> String {
    if b.len() < 16 { return "::".into(); }
    let groups: Vec<String> = b.chunks(2)
        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
        .collect();
    groups.join(":")
}

fn fmt_tcp_flags(f: u8) -> String {
    let mut v = Vec::new();
    if f & 0x02 != 0 { v.push("SYN"); }
    if f & 0x10 != 0 { v.push("ACK"); }
    if f & 0x08 != 0 { v.push("PSH"); }
    if f & 0x01 != 0 { v.push("FIN"); }
    if f & 0x04 != 0 { v.push("RST"); }
    if f & 0x20 != 0 { v.push("URG"); }
    if v.is_empty() { "NONE".into() } else { v.join(", ") }
}
