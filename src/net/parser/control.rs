use super::*;

pub(super) fn parse_igmp(
    t: &[u8],
    raw: &[u8],
    no: u64,
    ts: f64,
    src: String,
    dst: String,
    vlan: VlanCtx,
) -> Packet {
    let info = if t.len() >= 8 {
        let group = fmt_ip(&t[4..8]);
        match t[0] {
            0x11 => format!("Membership Query group={}", group),
            0x16 => format!("Membership Report v2 group={}", group),
            0x17 => format!("Leave Group {}", group),
            0x22 => "Membership Report v3".into(),
            _ => format!("IGMP type=0x{:02x}", t[0]),
        }
    } else {
        "IGMP".into()
    };
    Packet {
        capture: None,
        no,
        timestamp: ts,
        src,
        dst,
        protocol: "IGMP".into(),
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

pub(super) fn parse_gre(
    t: &[u8],
    raw: &[u8],
    no: u64,
    ts: f64,
    src: String,
    dst: String,
    vlan: VlanCtx,
) -> Packet {
    let encap = if t.len() >= 4 {
        match u16::from_be_bytes([t[2], t[3]]) {
            0x0800 => " (IPv4)",
            0x86DD => " (IPv6)",
            _ => "",
        }
    } else {
        ""
    };
    Packet {
        capture: None,
        no,
        timestamp: ts,
        src,
        dst,
        protocol: "GRE".into(),
        length: raw.len() as u16,
        info: format!("GRE Encapsulated{}", encap),
        src_port: None,
        dst_port: None,
        vlan_id: vlan.id,
        vlan_pcp: vlan.pcp,
        vlan_dei: vlan.dei,
        outer_vlan_id: vlan.outer_id,
        bytes: raw.to_vec(),
    }
}

pub(super) fn parse_esp(
    t: &[u8],
    raw: &[u8],
    no: u64,
    ts: f64,
    src: String,
    dst: String,
    vlan: VlanCtx,
) -> Packet {
    let spi = if t.len() >= 4 {
        format!("SPI=0x{:08x}", u32::from_be_bytes([t[0], t[1], t[2], t[3]]))
    } else {
        "SPI=?".into()
    };
    Packet {
        capture: None,
        no,
        timestamp: ts,
        src,
        dst,
        protocol: "ESP".into(),
        length: raw.len() as u16,
        info: format!("IPSec ESP {}", spi),
        src_port: None,
        dst_port: None,
        vlan_id: vlan.id,
        vlan_pcp: vlan.pcp,
        vlan_dei: vlan.dei,
        outer_vlan_id: vlan.outer_id,
        bytes: raw.to_vec(),
    }
}

pub(super) fn parse_ah(
    t: &[u8],
    raw: &[u8],
    no: u64,
    ts: f64,
    src: String,
    dst: String,
    vlan: VlanCtx,
) -> Packet {
    let spi = if t.len() >= 8 {
        format!("SPI=0x{:08x}", u32::from_be_bytes([t[4], t[5], t[6], t[7]]))
    } else {
        "SPI=?".into()
    };
    Packet {
        capture: None,
        no,
        timestamp: ts,
        src,
        dst,
        protocol: "AH".into(),
        length: raw.len() as u16,
        info: format!("IPSec AH {}", spi),
        src_port: None,
        dst_port: None,
        vlan_id: vlan.id,
        vlan_pcp: vlan.pcp,
        vlan_dei: vlan.dei,
        outer_vlan_id: vlan.outer_id,
        bytes: raw.to_vec(),
    }
}

pub(super) fn parse_vrrp(
    t: &[u8],
    raw: &[u8],
    no: u64,
    ts: f64,
    src: String,
    dst: String,
    vlan: VlanCtx,
) -> Packet {
    let info = if t.len() >= 4 {
        format!("VRRPv{} VRID={} Priority={}", t[0] >> 4, t[1], t[2])
    } else {
        "VRRP".into()
    };
    Packet {
        capture: None,
        no,
        timestamp: ts,
        src,
        dst,
        protocol: "VRRP".into(),
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

pub(super) fn parse_ospf(
    t: &[u8],
    raw: &[u8],
    no: u64,
    ts: f64,
    src: String,
    dst: String,
    vlan: VlanCtx,
) -> Packet {
    let msg = if t.len() >= 2 {
        match t[1] {
            1 => "Hello",
            2 => "DBD",
            3 => "LSR",
            4 => "LSU",
            5 => "LSAck",
            _ => "Unknown",
        }
    } else {
        "OSPF"
    };
    Packet {
        capture: None,
        no,
        timestamp: ts,
        src,
        dst,
        protocol: "OSPF".into(),
        length: raw.len() as u16,
        info: format!("OSPF {}", msg),
        src_port: None,
        dst_port: None,
        vlan_id: vlan.id,
        vlan_pcp: vlan.pcp,
        vlan_dei: vlan.dei,
        outer_vlan_id: vlan.outer_id,
        bytes: raw.to_vec(),
    }
}

pub(super) fn parse_eigrp(
    t: &[u8],
    raw: &[u8],
    no: u64,
    ts: f64,
    src: String,
    dst: String,
    vlan: VlanCtx,
) -> Packet {
    let op = t.get(1).copied().unwrap_or(0);
    Packet {
        capture: None,
        no,
        timestamp: ts,
        src,
        dst,
        protocol: "EIGRP".into(),
        length: raw.len() as u16,
        info: format!("EIGRP opcode={}", op),
        src_port: None,
        dst_port: None,
        vlan_id: vlan.id,
        vlan_pcp: vlan.pcp,
        vlan_dei: vlan.dei,
        outer_vlan_id: vlan.outer_id,
        bytes: raw.to_vec(),
    }
}

pub(super) fn parse_pim(
    t: &[u8],
    raw: &[u8],
    no: u64,
    ts: f64,
    src: String,
    dst: String,
    vlan: VlanCtx,
) -> Packet {
    let types = [
        "Hello",
        "Register",
        "Register-Stop",
        "Join/Prune",
        "Bootstrap",
        "Assert",
        "Graft",
        "State-Refresh",
        "Candidate-RP",
    ];
    let mt = (t.get(1).copied().unwrap_or(0) & 0x0F) as usize;
    let name = types.get(mt).copied().unwrap_or("Unknown");
    Packet {
        capture: None,
        no,
        timestamp: ts,
        src,
        dst,
        protocol: "PIM".into(),
        length: raw.len() as u16,
        info: format!("PIM {}", name),
        src_port: None,
        dst_port: None,
        vlan_id: vlan.id,
        vlan_pcp: vlan.pcp,
        vlan_dei: vlan.dei,
        outer_vlan_id: vlan.outer_id,
        bytes: raw.to_vec(),
    }
}
