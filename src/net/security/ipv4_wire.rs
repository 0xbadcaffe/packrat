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

pub(super) fn conflicting_fragment_frame(
    slices: &[FragmentSlice],
    fragment: &Ipv4Fragment<'_>,
) -> Option<u64> {
    let new_start = fragment.offset;
    let new_end = new_start.saturating_add(fragment.payload.len() as u32);
    slices.iter().find_map(|existing| {
        let existing_end = existing.start.saturating_add(existing.data.len() as u32);
        let overlap_start = new_start.max(existing.start);
        let overlap_end = new_end.min(existing_end);
        if overlap_start >= overlap_end {
            return None;
        }

        let new_offset = (overlap_start - new_start) as usize;
        let existing_offset = (overlap_start - existing.start) as usize;
        let overlap_len = (overlap_end - overlap_start) as usize;
        (fragment.payload[new_offset..new_offset + overlap_len]
            != existing.data[existing_offset..existing_offset + overlap_len])
            .then_some(existing.packet_no)
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
    let src: [u8; 4] = raw[ip_offset + 12..ip_offset + 16].try_into().ok()?;
    let dst: [u8; 4] = raw[ip_offset + 16..ip_offset + 20].try_into().ok()?;
    Some(parse_tcp_transport(
        &raw[ip_offset + ip_header_len..],
        total_len.saturating_sub(ip_header_len),
        Ipv4Addr::from(src).into(),
        Ipv4Addr::from(dst).into(),
        fragment_field & 0x2000 == 0,
    ))
}

pub(super) enum Ipv4DiscoveryProbe {
    EmptyUdp(u16),
    EchoRequest,
}

pub(super) fn ipv4_discovery_probe(raw: &[u8]) -> Option<Ipv4DiscoveryProbe> {
    let (offset, 0x0800) = ethernet_network_header(raw)? else { return None };
    let header = raw.get(offset..offset + 20)?;
    let header_len = usize::from(header[0] & 0x0f) * 4;
    let total_len = usize::from(u16_be_at(header, 2));
    if header[0] >> 4 != 4 || header_len < 20 || u16_be_at(header, 6) & 0x3fff != 0 {
        return None;
    }
    if [12, 16].into_iter().any(|start| {
        let address = Ipv4Addr::new(header[start], header[start + 1], header[start + 2], header[start + 3]);
        address.is_unspecified() || address.is_multicast() || address.is_broadcast()
    }) {
        return None;
    }
    let payload = raw.get(offset..offset + total_len)?.get(header_len..)?;
    match header[9] {
        1 if payload.len() >= 8 && payload.starts_with(&[8, 0]) => Some(Ipv4DiscoveryProbe::EchoRequest),
        17 if payload.len() == 8 && u16_be_at(payload, 4) == 8 => {
            let port = u16_be_at(payload, 2);
            (port != 0).then_some(Ipv4DiscoveryProbe::EmptyUdp(port))
        }
        _ => None,
    }
}

pub(super) fn parse_dhcp_message(raw: &[u8]) -> Option<DhcpMessage> {
    let (ip_offset, 0x0800) = ethernet_network_header(raw)? else {
        return None;
    };
    if raw.len() < ip_offset + 20 || raw[ip_offset] >> 4 != 4 || raw[ip_offset + 9] != 17 {
        return None;
    }
    let ip_header_len = usize::from(raw[ip_offset] & 0x0f) * 4;
    let total_len = usize::from(u16_be_at(raw, ip_offset + 2));
    let fragment = u16_be_at(raw, ip_offset + 6);
    if ip_header_len < 20 || fragment & 0x3fff != 0 {
        return None;
    }
    let ip = raw.get(ip_offset..ip_offset.checked_add(total_len)?)?;
    let udp = ip.get(ip_header_len..)?;
    let direction = match (u16_be_at(udp, 0), u16_be_at(udp, 2)) {
        (68, 67) => 1, // BOOTREQUEST
        (67, 68) => 2, // BOOTREPLY
        _ => return None,
    };
    let udp_len = usize::from(u16_be_at(udp, 4));
    let payload = udp.get(8..udp_len)?;
    let options = payload.get(240..)?;
    if payload[0] != direction || payload[236..240] != [99, 130, 83, 99] {
        return None;
    }

    let mut message_type = None;
    let mut client_identifier = None;
    let mut server_identifier = None;
    let mut cursor = 0;
    loop {
        let option = *options.get(cursor)?;
        cursor += 1;
        if option == 0 {
            continue;
        }
        if option == 255 {
            break;
        }
        let length = usize::from(*options.get(cursor)?);
        cursor += 1;
        let value = options.get(cursor..cursor + length)?;
        match option {
            53 if length == 1 && message_type.is_none() => message_type = Some(value[0]),
            54 if length == 4 && server_identifier.is_none() => {
                server_identifier = Some(std::net::Ipv4Addr::from(<[u8; 4]>::try_from(value).ok()?));
            }
            53 | 54 => return None,
            61 if !value.is_empty() => client_identifier = Some(value.to_vec()),
            _ => {}
        }
        cursor += length;
    }

    let message_type = message_type?;
    if !matches!((direction, message_type), (1, 1) | (2, 2 | 5)) {
        return None;
    }
    let hardware_len = usize::from(payload[2]);
    if hardware_len > 16 {
        return None;
    }
    let client_identity =
        client_identifier.unwrap_or_else(|| payload[28..28 + hardware_len].to_vec());
    Some(DhcpMessage {
        message_type,
        client_identity,
        server_identifier,
    })
}
