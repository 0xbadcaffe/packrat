use super::*;

// ─── Layer-4 dispatcher ───────────────────────────────────────────────────────

pub(super) fn parse_transport(
    transport: &[u8],
    raw: &[u8],
    no: u64,
    ts: f64,
    proto_num: u8,
    src_ip: String,
    dst_ip: String,
    vlan: VlanCtx,
) -> Packet {
    match proto_num {
        1 => parse_icmp(transport, raw, no, ts, src_ip, dst_ip, vlan),
        2 => parse_igmp(transport, raw, no, ts, src_ip, dst_ip, vlan),
        6 => parse_tcp(transport, raw, no, ts, src_ip, dst_ip, vlan),
        17 => parse_udp(transport, raw, no, ts, src_ip, dst_ip, vlan),
        47 => parse_gre(transport, raw, no, ts, src_ip, dst_ip, vlan),
        50 => parse_esp(transport, raw, no, ts, src_ip, dst_ip, vlan),
        51 => parse_ah(transport, raw, no, ts, src_ip, dst_ip, vlan),
        58 => parse_icmpv6(transport, raw, no, ts, src_ip, dst_ip, vlan),
        89 => parse_ospf(transport, raw, no, ts, src_ip, dst_ip, vlan),
        88 => parse_eigrp(transport, raw, no, ts, src_ip, dst_ip, vlan),
        103 => parse_pim(transport, raw, no, ts, src_ip, dst_ip, vlan),
        112 => parse_vrrp(transport, raw, no, ts, src_ip, dst_ip, vlan),
        _ => Packet {
            capture: None,
            no,
            timestamp: ts,
            src: src_ip,
            dst: dst_ip,
            protocol: format!("IP({})", proto_num),
            length: raw.len() as u16,
            info: "Unknown IP protocol".into(),
            src_port: None,
            dst_port: None,
            vlan_id: vlan.id,
            vlan_pcp: vlan.pcp,
            vlan_dei: vlan.dei,
            outer_vlan_id: vlan.outer_id,
            bytes: raw.to_vec(),
        },
    }
}

// ─── Transport parsers ────────────────────────────────────────────────────────

pub(super) fn parse_icmp(
    t: &[u8],
    raw: &[u8],
    no: u64,
    ts: f64,
    src: String,
    dst: String,
    vlan: VlanCtx,
) -> Packet {
    let info = if t.len() >= 2 {
        match t[0] {
            0 => "Echo reply".into(),
            8 => "Echo request".into(),
            3 => "Destination unreachable".into(),
            11 => "Time exceeded".into(),
            _ => format!("ICMP type={}", t[0]),
        }
    } else {
        "ICMP".into()
    };
    Packet {
        capture: None,
        no,
        timestamp: ts,
        src,
        dst,
        protocol: "ICMP".into(),
        length: raw.len() as u16,
        info,
        src_port: None,
        dst_port: None,
        vlan_id: vlan.id,
        vlan_pcp: vlan.pcp,
        vlan_dei: vlan.dei,
        outer_vlan_id: vlan.outer_id,
        bytes: raw.to_vec(),
    }
}

pub(super) fn parse_icmpv6(
    t: &[u8],
    raw: &[u8],
    no: u64,
    ts: f64,
    src: String,
    dst: String,
    vlan: VlanCtx,
) -> Packet {
    let info = if t.len() >= 2 {
        match t[0] {
            128 => "Echo request".into(),
            129 => "Echo reply".into(),
            133 => "Router solicitation".into(),
            134 => "Router advertisement".into(),
            135 => "Neighbor solicitation".into(),
            136 => "Neighbor advertisement".into(),
            _ => format!("ICMPv6 type={}", t[0]),
        }
    } else {
        "ICMPv6".into()
    };
    Packet {
        capture: None,
        no,
        timestamp: ts,
        src,
        dst,
        protocol: "ICMPv6".into(),
        length: raw.len() as u16,
        info,
        src_port: None,
        dst_port: None,
        vlan_id: vlan.id,
        vlan_pcp: vlan.pcp,
        vlan_dei: vlan.dei,
        outer_vlan_id: vlan.outer_id,
        bytes: raw.to_vec(),
    }
}

pub(super) fn parse_tcp(
    t: &[u8],
    raw: &[u8],
    no: u64,
    ts: f64,
    src: String,
    dst: String,
    vlan: VlanCtx,
) -> Packet {
    if t.len() < 20 {
        return Packet {
            capture: None,
            no,
            timestamp: ts,
            src,
            dst,
            protocol: "TCP".into(),
            length: raw.len() as u16,
            info: "TCP (truncated)".into(),
            src_port: None,
            dst_port: None,
            vlan_id: vlan.id,
            vlan_pcp: vlan.pcp,
            vlan_dei: vlan.dei,
            outer_vlan_id: vlan.outer_id,
            bytes: raw.to_vec(),
        };
    }
    let sp = u16::from_be_bytes([t[0], t[1]]);
    let dp = u16::from_be_bytes([t[2], t[3]]);
    let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
    let flags = t[13];
    let info = format!("{} → {} [{}] Seq={}", sp, dp, fmt_tcp_flags(flags), seq);
    Packet {
        capture: None,
        no,
        timestamp: ts,
        src,
        dst,
        protocol: classify_tcp(sp, dp).into(),
        length: raw.len() as u16,
        info,
        src_port: Some(sp),
        dst_port: Some(dp),
        vlan_id: vlan.id,
        vlan_pcp: vlan.pcp,
        vlan_dei: vlan.dei,
        outer_vlan_id: vlan.outer_id,
        bytes: raw.to_vec(),
    }
}

pub(super) fn parse_udp(
    t: &[u8],
    raw: &[u8],
    no: u64,
    ts: f64,
    src: String,
    dst: String,
    vlan: VlanCtx,
) -> Packet {
    if t.len() < 8 {
        return Packet {
            capture: None,
            no,
            timestamp: ts,
            src,
            dst,
            protocol: "UDP".into(),
            length: raw.len() as u16,
            info: "UDP (truncated)".into(),
            src_port: None,
            dst_port: None,
            vlan_id: vlan.id,
            vlan_pcp: vlan.pcp,
            vlan_dei: vlan.dei,
            outer_vlan_id: vlan.outer_id,
            bytes: raw.to_vec(),
        };
    }
    let sp = u16::from_be_bytes([t[0], t[1]]);
    let dp = u16::from_be_bytes([t[2], t[3]]);
    let payload_len = (t.len() as u16).saturating_sub(8);
    // Heuristic: RTP has version=2 in first two bits of byte 8
    let proto = {
        let p = classify_udp(sp, dp);
        if p == "UDP" && t.len() >= 12 && (t[8] >> 6) == 2 {
            "RTP"
        } else {
            p
        }
    };
    Packet {
        capture: None,
        no,
        timestamp: ts,
        src,
        dst,
        protocol: proto.into(),
        length: raw.len() as u16,
        info: format!("{} → {} Len={}", sp, dp, payload_len),
        src_port: Some(sp),
        dst_port: Some(dp),
        vlan_id: vlan.id,
        vlan_pcp: vlan.pcp,
        vlan_dei: vlan.dei,
        outer_vlan_id: vlan.outer_id,
        bytes: raw.to_vec(),
    }
}
