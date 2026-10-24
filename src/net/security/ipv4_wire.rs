use super::*;

pub(super) fn parse_ipv4_fragment(raw: &[u8]) -> Option<Ipv4Fragment<'_>> {
    let (ip_offset, ether_type) = ethernet_network_header(raw)?;
    if ether_type != 0x0800 || raw.len() < ip_offset + 20 || raw[ip_offset] >> 4 != 4 {
        return None;
    }

    let header_len = usize::from(raw[ip_offset] & 0x0f) * 4;
    let flags_and_offset = u16::from_be_bytes([raw[ip_offset + 6], raw[ip_offset + 7]]);
    let offset = u32::from(flags_and_offset & 0x1fff) * 8;
    let more_fragments = flags_and_offset & 0x2000 != 0;
    if !more_fragments && offset == 0 {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([raw[ip_offset + 2], raw[ip_offset + 3]]));
    let malformed_length = header_len < 20 || total_len < header_len;
    let declared_payload_len = total_len.saturating_sub(header_len);
    let payload_start = ip_offset.saturating_add(header_len).min(raw.len());
    let captured_payload_len = declared_payload_len.min(raw.len().saturating_sub(payload_start));
    let payload = &raw[payload_start..payload_start + captured_payload_len];

    Some(Ipv4Fragment {
        key: FragmentKey {
            src: raw[ip_offset + 12..ip_offset + 16].try_into().ok()?,
            dst: raw[ip_offset + 16..ip_offset + 20].try_into().ok()?,
            identification: u16::from_be_bytes([raw[ip_offset + 4], raw[ip_offset + 5]]),
            protocol: raw[ip_offset + 9],
        },
        offset,
        more_fragments,
        payload,
        declared_payload_len,
        malformed_length,
    })
}

pub(super) fn ethernet_network_header(raw: &[u8]) -> Option<(usize, u16)> {
    if raw.len() < 14 {
        return None;
    }
    let mut ether_type_offset = 12usize;
    loop {
        let ether_type = u16::from_be_bytes([
            *raw.get(ether_type_offset)?,
            *raw.get(ether_type_offset + 1)?,
        ]);
        if ether_type != 0x8100 && ether_type != 0x88a8 {
            return Some((ether_type_offset + 2, ether_type));
        }
        ether_type_offset = ether_type_offset.checked_add(4)?;
    }
}

pub(super) fn has_conflicting_fragment_overlap(
    slices: &[FragmentSlice],
    fragment: &Ipv4Fragment<'_>,
) -> bool {
    let new_start = fragment.offset;
    let new_end = new_start.saturating_add(fragment.payload.len() as u32);
    slices.iter().any(|existing| {
        let existing_end = existing.start.saturating_add(existing.data.len() as u32);
        let overlap_start = new_start.max(existing.start);
        let overlap_end = new_end.min(existing_end);
        if overlap_start >= overlap_end {
            return false;
        }

        let new_offset = (overlap_start - new_start) as usize;
        let existing_offset = (overlap_start - existing.start) as usize;
        let overlap_len = (overlap_end - overlap_start) as usize;
        fragment.payload[new_offset..new_offset + overlap_len]
            != existing.data[existing_offset..existing_offset + overlap_len]
    })
}

pub(super) fn parse_ipv4_tcp_frame(raw: &[u8]) -> Option<TcpFrame<'_>> {
    let (ip_offset, ether_type) = ethernet_network_header(raw)?;
    if ether_type != 0x0800 || raw.len() < ip_offset + 20 || raw[ip_offset] >> 4 != 4 {
        return None;
    }
    let ip_header_len = usize::from(raw[ip_offset] & 0x0f) * 4;
    if ip_header_len < 20 || raw.len() < ip_offset + ip_header_len || raw[ip_offset + 9] != 6 {
        return None;
    }

    let fragment_field = u16::from_be_bytes([raw[ip_offset + 6], raw[ip_offset + 7]]);
    if fragment_field & 0x1fff != 0 {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([raw[ip_offset + 2], raw[ip_offset + 3]]));
    if total_len < ip_header_len + 20 {
        return Some(TcpFrame::Malformed(
            "IPv4 payload is shorter than a minimum TCP header",
        ));
    }
    let tcp_offset = ip_offset + ip_header_len;
    if raw.len() < tcp_offset + 20 {
        return Some(TcpFrame::Malformed("captured TCP header is truncated"));
    }

    let tcp_header_len = usize::from(raw[tcp_offset + 12] >> 4) * 4;
    if tcp_header_len < 20 {
        return Some(TcpFrame::Malformed(
            "TCP data offset is smaller than 20 bytes",
        ));
    }
    if total_len < ip_header_len + tcp_header_len {
        return Some(TcpFrame::Malformed(
            "TCP data offset exceeds the IPv4 payload length",
        ));
    }

    let src: [u8; 4] = raw[ip_offset + 12..ip_offset + 16].try_into().ok()?;
    let dst: [u8; 4] = raw[ip_offset + 16..ip_offset + 20].try_into().ok()?;
    let src_port = u16::from_be_bytes([raw[tcp_offset], raw[tcp_offset + 1]]);
    let dst_port = u16::from_be_bytes([raw[tcp_offset + 2], raw[tcp_offset + 3]]);
    let src_endpoint = (src, src_port);
    let dst_endpoint = (dst, dst_port);
    let (endpoint_a, endpoint_b, from_a) = if src_endpoint <= dst_endpoint {
        (src_endpoint, dst_endpoint, true)
    } else {
        (dst_endpoint, src_endpoint, false)
    };
    let sequence = u32::from_be_bytes(raw[tcp_offset + 4..tcp_offset + 8].try_into().ok()?);
    let packet_end = (ip_offset + total_len).min(raw.len());
    let payload_start = (tcp_offset + tcp_header_len).min(packet_end);

    Some(TcpFrame::Segment(TcpSegment {
        key: TcpFlowKey {
            endpoint_a,
            endpoint_b,
        },
        from_a,
        sequence,
        flags: raw[tcp_offset + 13],
        payload: &raw[payload_start..packet_end],
    }))
}

pub(super) fn is_empty_ipv4_udp_probe(raw: &[u8]) -> bool {
    let Some((ip_offset, 0x0800)) = ethernet_network_header(raw) else {
        return false;
    };
    if raw.len() < ip_offset + 20 || raw[ip_offset] >> 4 != 4 || raw[ip_offset + 9] != 17 {
        return false;
    }
    let ip_header_len = usize::from(raw[ip_offset] & 0x0f) * 4;
    let udp_offset = ip_offset + ip_header_len;
    if ip_header_len < 20 || raw.len() < udp_offset + 8 {
        return false;
    }
    u16::from_be_bytes([raw[udp_offset + 4], raw[udp_offset + 5]]) == 8
}

pub(super) fn parse_dhcp_message(raw: &[u8]) -> Option<DhcpMessage> {
    let (ip_offset, 0x0800) = ethernet_network_header(raw)? else {
        return None;
    };
    if raw.len() < ip_offset + 20 || raw[ip_offset] >> 4 != 4 || raw[ip_offset + 9] != 17 {
        return None;
    }
    let ip_header_len = usize::from(raw[ip_offset] & 0x0f) * 4;
    let udp_offset = ip_offset.checked_add(ip_header_len)?;
    if ip_header_len < 20 || raw.len() < udp_offset + 8 {
        return None;
    }
    let source_port = u16::from_be_bytes([raw[udp_offset], raw[udp_offset + 1]]);
    let destination_port = u16::from_be_bytes([raw[udp_offset + 2], raw[udp_offset + 3]]);
    if !matches!((source_port, destination_port), (67, 68) | (68, 67)) {
        return None;
    }
    let udp_len = usize::from(u16::from_be_bytes([
        raw[udp_offset + 4],
        raw[udp_offset + 5],
    ]));
    let payload_start = udp_offset + 8;
    let payload_end = (udp_offset + udp_len).min(raw.len());
    if payload_end < payload_start + 240 {
        return None;
    }
    let payload = &raw[payload_start..payload_end];
    if payload[236..240] != [99, 130, 83, 99] {
        return None;
    }

    let mut message_type = None;
    let mut client_identifier = None;
    let mut server_identifier = None;
    let mut cursor = 240usize;
    while cursor < payload.len() {
        let option = payload[cursor];
        cursor += 1;
        if option == 0 {
            continue;
        }
        if option == 255 {
            break;
        }
        let length = usize::from(*payload.get(cursor)?);
        cursor += 1;
        let value = payload.get(cursor..cursor + length)?;
        match option {
            53 if length == 1 => message_type = Some(value[0]),
            54 if length == 4 => server_identifier = Some(value.to_vec()),
            61 if !value.is_empty() => client_identifier = Some(value.to_vec()),
            _ => {}
        }
        cursor += length;
    }

    let hardware_len = usize::from(payload[2]).min(16);
    let client_identity =
        client_identifier.unwrap_or_else(|| payload[28..28 + hardware_len].to_vec());
    let mut server_identity =
        server_identifier.unwrap_or_else(|| raw[ip_offset + 12..ip_offset + 16].to_vec());
    if let Some(source_mac) = ethernet_source_mac(raw) {
        server_identity.extend_from_slice(&source_mac);
    }
    Some(DhcpMessage {
        message_type: message_type?,
        client_identity,
        server_identity,
    })
}
