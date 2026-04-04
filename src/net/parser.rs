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
        6 => parse_tcp(transport, raw, no, ts, src_ip, dst_ip, vlan_id),
        17 => parse_udp(transport, raw, no, ts, src_ip, dst_ip, vlan_id),
        58 => parse_icmpv6(transport, raw, no, ts, src_ip, dst_ip, vlan_id),
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
        _                       => "UDP",
    }
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
