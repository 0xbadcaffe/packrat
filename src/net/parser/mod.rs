// These functions are called from live.rs (real-capture feature only).
#![allow(dead_code)]
use crate::net::packet::Packet;

pub fn parse_captured(
    data: &[u8],
    no: u64,
    capture: crate::net::packet::CaptureMetadata,
) -> Result<Packet, String> {
    if capture.captured_length as usize != data.len()
        || capture.wire_length < capture.captured_length
        || data.len() > 1_048_576
    {
        return Err("Invalid captured packet lengths".into());
    }
    let timestamp = capture.timestamp.map_or(0.0, |time| time.seconds());
    let mut packet = if capture.link_type == 1 {
        parse_ethernet(data, no, timestamp)
    } else {
        let mut packet = unknown(data, no, timestamp);
        packet.info = format!("Undecoded capture link type {}", capture.link_type);
        packet
    };
    packet.length = data.len().min(u16::MAX as usize) as u16;
    packet.capture = Some(capture);
    Ok(packet)
}

// ─── VLAN context ─────────────────────────────────────────────────────────────

/// All VLAN tag metadata extracted from one Ethernet frame.
/// Passed as a single value through the parser call chain so the Packet
/// struct can be populated without threading four separate Option<_>s.
#[derive(Default, Clone, Copy)]
pub struct VlanCtx {
    /// Inner VLAN ID (C-TAG 0x8100), or the only tag for single-tagged frames.
    pub id: Option<u16>,
    /// 802.1p Priority Code Point (3 bits, 0-7).
    pub pcp: Option<u8>,
    /// Drop Eligible Indicator (1 bit).
    pub dei: Option<u8>,
    /// Outer / provider VLAN ID (S-TAG 0x88a8) for QinQ frames.
    pub outer_id: Option<u16>,
}

impl VlanCtx {
    /// Returns true when two VLAN tags were present (QinQ / 802.1ad).
    pub fn is_qinq(self) -> bool {
        self.outer_id.is_some()
    }
}

// ─── Ethernet entry point ─────────────────────────────────────────────────────

/// Parse a raw Ethernet frame into a `Packet`.
pub fn parse_ethernet(data: &[u8], no: u64, ts: f64) -> Packet {
    if data.len() < 14 {
        return unknown(data, no, ts);
    }

    let mut offset = 12usize; // position of EtherType field
    let mut vlan = VlanCtx::default();
    let mut tag_count = 0u8;

    // Strip 802.1Q (0x8100) and 802.1ad S-TAG (0x88a8) VLAN tags.
    // First tag = outer; second = inner (QinQ).
    loop {
        if offset + 2 > data.len() {
            return unknown(data, no, ts);
        }
        let etype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        if etype == 0x8100 || etype == 0x88a8 {
            if offset + 4 > data.len() {
                return unknown(data, no, ts);
            }
            let tci = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let vid = tci & 0x0FFF;
            let pcp = ((tci >> 13) & 0x07) as u8;
            let dei = ((tci >> 12) & 0x01) as u8;
            tag_count += 1;
            if tag_count == 1 {
                vlan.id = Some(vid);
                vlan.pcp = Some(pcp);
                vlan.dei = Some(dei);
            } else {
                // Second tag is the inner C-TAG; promote first to outer.
                vlan.outer_id = vlan.id;
                vlan.id = Some(vid);
                vlan.pcp = Some(pcp);
                vlan.dei = Some(dei);
            }
            offset += 4;
        } else {
            break;
        }
    }

    let ether_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let payload = &data[offset + 2..];

    match ether_type {
        0x0806 => parse_arp(payload, data, no, ts, vlan),
        0x0800 => parse_ipv4(payload, data, no, ts, vlan),
        0x86DD => parse_ipv6(payload, data, no, ts, vlan),
        0x8847 | 0x8848 => parse_mpls(payload, data, no, ts, vlan),
        0x8863 => parse_pppoe(payload, data, no, ts, vlan, "discovery"),
        0x8864 => parse_pppoe(payload, data, no, ts, vlan, "session"),
        _ => unknown(data, no, ts),
    }
}

// ─── Layer-2 ──────────────────────────────────────────────────────────────────

fn parse_arp(payload: &[u8], raw: &[u8], no: u64, ts: f64, vlan: VlanCtx) -> Packet {
    if payload.len() < 28 {
        return unknown(raw, no, ts);
    }
    let src = fmt_ip(&payload[14..18]);
    let dst = fmt_ip(&payload[24..28]);
    let opcode = u16::from_be_bytes([payload[6], payload[7]]);
    let op_str = if opcode == 1 { "request" } else { "reply" };
    Packet {
        capture: None,
        no,
        timestamp: ts,
        src: src.clone(),
        dst: dst.clone(),
        protocol: "ARP".into(),
        length: raw.len() as u16,
        info: format!("Who has {}? Tell {} ({})", dst, src, op_str),
        src_port: None,
        dst_port: None,
        vlan_id: vlan.id,
        vlan_pcp: vlan.pcp,
        vlan_dei: vlan.dei,
        outer_vlan_id: vlan.outer_id,
        bytes: raw.to_vec(),
    }
}

fn parse_mpls(payload: &[u8], raw: &[u8], no: u64, ts: f64, vlan: VlanCtx) -> Packet {
    let label = if payload.len() >= 4 {
        (u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) >> 12) & 0xFFFFF
    } else {
        0
    };
    Packet {
        capture: None,
        no,
        timestamp: ts,
        src: "?.?.?.?".into(),
        dst: "?.?.?.?".into(),
        protocol: "MPLS".into(),
        length: raw.len() as u16,
        info: format!("MPLS Label={}", label),
        src_port: None,
        dst_port: None,
        vlan_id: vlan.id,
        vlan_pcp: vlan.pcp,
        vlan_dei: vlan.dei,
        outer_vlan_id: vlan.outer_id,
        bytes: raw.to_vec(),
    }
}

fn parse_pppoe(payload: &[u8], raw: &[u8], no: u64, ts: f64, vlan: VlanCtx, kind: &str) -> Packet {
    let info = if kind == "session" {
        let sid = if payload.len() >= 4 {
            u16::from_be_bytes([payload[2], payload[3]])
        } else {
            0
        };
        format!("PPPoE Session id=0x{:04x}", sid)
    } else {
        let code = payload.get(1).copied().unwrap_or(0);
        match code {
            0x09 => "PPPoE PADI".into(),
            0x07 => "PPPoE PADO".into(),
            0x19 => "PPPoE PADR".into(),
            0x65 => "PPPoE PADS".into(),
            0xa7 => "PPPoE PADT".into(),
            _ => format!("PPPoE code=0x{:02x}", code),
        }
    };
    Packet {
        capture: None,
        no,
        timestamp: ts,
        src: "?.?.?.?".into(),
        dst: "?.?.?.?".into(),
        protocol: "PPPoE".into(),
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

fn unknown(raw: &[u8], no: u64, ts: f64) -> Packet {
    Packet {
        capture: None,
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
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes: raw.to_vec(),
    }
}

mod network;
use network::*;
mod transport;
use transport::*;
mod classify;
use classify::*;

mod control;
use control::*;
