use super::*;

/// Compute the byte offset where the TCP payload begins, reading IHL and the
/// TCP data-offset field from the raw frame rather than assuming fixed headers.
pub fn tcp_payload_offset(pkt: &Packet) -> usize {
    tcp_payload_offset_checked(pkt).unwrap_or(pkt.bytes.len())
}

pub(super) fn tcp_payload_offset_checked(pkt: &Packet) -> Option<usize> {
    let raw = &pkt.bytes;
    let tp_off = tcp_transport_offset(pkt)?;
    let data_offset = raw.get(tp_off + 12)?;
    let tcp_hdr = usize::from(data_offset >> 4) * 4;
    if tcp_hdr < 20 {
        return None;
    }
    tp_off
        .checked_add(tcp_hdr)
        .filter(|offset| *offset <= raw.len())
}

pub(super) fn tcp_transport_offset(pkt: &Packet) -> Option<usize> {
    let raw = &pkt.bytes;
    let eth_extra = match (pkt.outer_vlan_id.is_some(), pkt.vlan_id.is_some()) {
        (true, _) => 8, // QinQ: two 4-byte tags
        (false, true) => 4,
        (false, false) => 0,
    };
    let ip_off = 14usize.checked_add(eth_extra)?;
    let version = raw.get(ip_off)? >> 4;
    match version {
        4 => {
            let ihl = usize::from(raw.get(ip_off)? & 0x0f) * 4;
            if ihl < 20 || *raw.get(ip_off + 9)? != 6 {
                return None;
            }
            ip_off
                .checked_add(ihl)
                .filter(|offset| *offset <= raw.len())
        }
        6 => ipv6_tcp_offset(raw, ip_off),
        _ => None,
    }
}

pub(super) fn ipv6_tcp_offset(raw: &[u8], ip_off: usize) -> Option<usize> {
    let mut next_header = *raw.get(ip_off + 6)?;
    let mut offset = ip_off.checked_add(40)?;
    if offset > raw.len() {
        return None;
    }

    for _ in 0..16 {
        match next_header {
            6 => return Some(offset),
            0 | 43 | 60 => {
                next_header = *raw.get(offset)?;
                let length = (usize::from(*raw.get(offset + 1)?) + 1) * 8;
                offset = offset.checked_add(length)?;
            }
            44 => {
                next_header = *raw.get(offset)?;
                offset = offset.checked_add(8)?;
            }
            51 => {
                next_header = *raw.get(offset)?;
                let length = (usize::from(*raw.get(offset + 1)?) + 2) * 4;
                offset = offset.checked_add(length)?;
            }
            _ => return None,
        }
        if offset > raw.len() {
            return None;
        }
    }
    None
}
