use super::*;

// ─── Layer-3 ──────────────────────────────────────────────────────────────────

pub(super) fn parse_ipv4(payload: &[u8], raw: &[u8], no: u64, ts: f64, vlan: VlanCtx) -> Packet {
    if payload.len() < 20 || payload[0] >> 4 != 4 {
        return unknown(raw, no, ts);
    }
    let ihl = ((payload[0] & 0x0F) as usize) * 4;
    let packet_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if ihl < 20 || packet_len < ihl || packet_len > payload.len() {
        return unknown(raw, no, ts);
    }
    let proto_num = payload[9];
    let src_ip = fmt_ip(&payload[12..16]);
    let dst_ip = fmt_ip(&payload[16..20]);
    let fragment_field = u16::from_be_bytes([payload[6], payload[7]]);
    if fragment_field & 0x1fff != 0 {
        return Packet {
            capture: None,
            no,
            timestamp: ts,
            src: src_ip,
            dst: dst_ip,
            protocol: "IPv4-FRAG".into(),
            length: raw.len() as u16,
            info: "IPv4 non-initial fragment".into(),
            src_port: None,
            dst_port: None,
            vlan_id: vlan.id,
            vlan_pcp: vlan.pcp,
            vlan_dei: vlan.dei,
            outer_vlan_id: vlan.outer_id,
            bytes: raw.to_vec(),
        };
    }
    parse_transport(
        &payload[ihl..packet_len],
        raw,
        no,
        ts,
        proto_num,
        src_ip,
        dst_ip,
        vlan,
    )
}

pub(super) fn parse_ipv6(payload: &[u8], raw: &[u8], no: u64, ts: f64, vlan: VlanCtx) -> Packet {
    if payload.len() < 40 {
        return unknown(raw, no, ts);
    }
    let payload_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let packet_len = match 40usize.checked_add(payload_len) {
        Some(len) if len <= payload.len() => len,
        _ => return unknown(raw, no, ts),
    };
    let src_ip = fmt_ipv6(&payload[8..24]);
    let dst_ip = fmt_ipv6(&payload[24..40]);
    let mut next_header = payload[6];
    let mut offset = 40usize;

    // Walk the extension headers whose lengths can be determined without
    // interpreting their payload. The bound prevents malformed chains from
    // consuming unbounded work.
    for _ in 0..16 {
        let extension_len = match next_header {
            0 | 43 | 60 => {
                let header = match payload.get(offset..packet_len) {
                    Some(header) if header.len() >= 2 => header,
                    _ => return unknown(raw, no, ts),
                };
                next_header = header[0];
                (usize::from(header[1]) + 1) * 8
            }
            44 => {
                let header = match payload.get(offset..packet_len) {
                    Some(header) if header.len() >= 8 => header,
                    _ => return unknown(raw, no, ts),
                };
                next_header = header[0];
                let fragment_field = u16::from_be_bytes([header[2], header[3]]);
                if fragment_field & 0xfff8 != 0 {
                    return Packet {
                        capture: None,
                        no,
                        timestamp: ts,
                        src: src_ip,
                        dst: dst_ip,
                        protocol: "IPv6-FRAG".into(),
                        length: raw.len() as u16,
                        info: "IPv6 non-initial fragment".into(),
                        src_port: None,
                        dst_port: None,
                        vlan_id: vlan.id,
                        vlan_pcp: vlan.pcp,
                        vlan_dei: vlan.dei,
                        outer_vlan_id: vlan.outer_id,
                        bytes: raw.to_vec(),
                    };
                }
                8
            }
            _ => break,
        };
        offset = match offset.checked_add(extension_len) {
            Some(end) if end <= packet_len => end,
            _ => return unknown(raw, no, ts),
        };
    }

    if matches!(next_header, 0 | 43 | 44 | 60) {
        return unknown(raw, no, ts);
    }
    parse_transport(
        &payload[offset..packet_len],
        raw,
        no,
        ts,
        next_header,
        src_ip,
        dst_ip,
        vlan,
    )
}
