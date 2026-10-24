use super::*;

pub(super) fn parse_ipv6_inspection(raw: &[u8]) -> Option<Ipv6Inspection<'_>> {
    let (ip_offset, ether_type) = ethernet_network_header(raw)?;
    if ether_type != 0x86dd || raw.len() < ip_offset + 40 || raw[ip_offset] >> 4 != 6 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([raw[ip_offset + 4], raw[ip_offset + 5]]));
    let packet_end = (ip_offset + 40 + payload_len).min(raw.len());
    let mut next_header = raw[ip_offset + 6];
    let mut cursor = ip_offset + 40;
    let mut extension_count = 0usize;

    while matches!(next_header, 0 | 43 | 44 | 51 | 60) && cursor < packet_end {
        extension_count += 1;
        if extension_count > 32 {
            break;
        }
        let current = next_header;
        next_header = *raw.get(cursor)?;
        let length = match current {
            44 => 8,
            51 => (usize::from(*raw.get(cursor + 1)?) + 2) * 4,
            _ => (usize::from(*raw.get(cursor + 1)?) + 1) * 8,
        };
        cursor = cursor.checked_add(length)?;
    }

    Some(Ipv6Inspection {
        hop_limit: raw[ip_offset + 7],
        source: raw[ip_offset + 8..ip_offset + 24].try_into().ok()?,
        next_header,
        extension_count,
        transport: if cursor <= packet_end {
            &raw[cursor..packet_end]
        } else {
            &[]
        },
    })
}

pub(super) fn is_ipv6_link_local(address: &[u8; 16]) -> bool {
    address[0] == 0xfe && address[1] & 0xc0 == 0x80
}

pub(super) fn ethernet_source_mac(raw: &[u8]) -> Option<[u8; 6]> {
    raw.get(6..12)?.try_into().ok()
}

pub(super) fn ndp_target_link_layer_address(mut options: &[u8]) -> Option<[u8; 6]> {
    while options.len() >= 2 {
        let option_type = options[0];
        let option_len = usize::from(options[1]) * 8;
        if option_len == 0 || option_len > options.len() {
            return None;
        }
        if option_type == 2 && option_len >= 8 {
            return options[2..8].try_into().ok();
        }
        options = &options[option_len..];
    }
    None
}

pub(super) fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub(super) fn is_stp_topology_change(raw: &[u8]) -> bool {
    raw.len() >= 22
        && raw[..6] == [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]
        && raw[14..17] == [0x42, 0x42, 0x03]
        && raw[17..19] == [0x00, 0x00]
        && (raw[20] == 0x80 || raw[21] & 0x81 != 0)
}

pub(super) fn lldp_chassis_identity(raw: &[u8]) -> Option<([u8; 6], Vec<u8>)> {
    let (payload_offset, ether_type) = ethernet_network_header(raw)?;
    if ether_type != 0x88cc {
        return None;
    }
    let source_mac = ethernet_source_mac(raw)?;
    let mut cursor = payload_offset;
    while cursor + 2 <= raw.len() {
        let header = u16::from_be_bytes([raw[cursor], raw[cursor + 1]]);
        let tlv_type = (header >> 9) as u8;
        let length = usize::from(header & 0x01ff);
        cursor += 2;
        if cursor + length > raw.len() {
            return None;
        }
        if tlv_type == 0 {
            return None;
        }
        if tlv_type == 1 && length >= 2 {
            return Some((source_mac, raw[cursor..cursor + length].to_vec()));
        }
        cursor += length;
    }
    None
}
