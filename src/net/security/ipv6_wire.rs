use super::*;

pub(super) fn parse_ipv6_inspection(raw: &[u8]) -> Option<Ipv6Inspection<'_>> {
    let (ip_offset, ether_type) = ethernet_network_header(raw)?;
    if ether_type != 0x86dd || raw.len() < ip_offset + 40 || raw[ip_offset] >> 4 != 6 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([raw[ip_offset + 4], raw[ip_offset + 5]]));
    let declared_end = ip_offset + 40 + payload_len;
    let packet_end = declared_end.min(raw.len());
    let mut next_header = raw[ip_offset + 6];
    let mut transport = &raw[ip_offset + 40..packet_end];
    let mut declared_transport_len = payload_len;
    let mut extension_count = 0usize;
    let mut fragmented = false;

    while matches!(next_header, 0 | 43 | 44 | 51 | 60) {
        let current = next_header;
        let Some(&[following, length_field]) = transport.first_chunk::<2>() else {
            transport = &[];
            break;
        };
        let length = match current {
            44 => 8,
            51 => (usize::from(length_field) + 2) * 4,
            _ => (usize::from(length_field) + 1) * 8,
        };
        let Some(rest) = transport.get(length..) else {
            transport = &[];
            break;
        };
        extension_count += 1;
        next_header = following;
        declared_transport_len -= length;
        fragmented |= current == 44;
        // A non-initial fragment does not begin at the next protocol header.
        if extension_count > 32
            || (current == 44 && u16::from_be_bytes([transport[2], transport[3]]) & 0xfff8 != 0)
        {
            transport = &[];
            break;
        }
        transport = rest;
    }

    Some(Ipv6Inspection {
        declared_transport_len,
        hop_limit: raw[ip_offset + 7],
        source: raw[ip_offset + 8..ip_offset + 24].try_into().ok()?,
        destination: raw[ip_offset + 24..ip_offset + 40].try_into().ok()?,
        next_header,
        extension_count,
        fragmented,
        complete: declared_end <= raw.len(),
        transport,
    })
}

pub(super) fn ipv6_probe(raw: &[u8]) -> Option<Ipv6Probe> {
    let packet = parse_ipv6_inspection(raw)?;
    if packet.fragmented || !packet.complete || packet.extension_count > 32
        || [packet.source, packet.destination].into_iter().any(|address| {
            let address = std::net::Ipv6Addr::from(address);
            address.is_multicast() || address.is_unspecified()
        })
    {
        return None;
    }
    let transport = packet.transport;
    let read_port = |offset| Some(u16::from_be_bytes(transport.get(offset..offset + 2)?.try_into().ok()?));
    match packet.next_header {
        6 if transport.len() >= 20 => {
            let header_length = usize::from(transport[12] >> 4) * 4;
            if !(20..=transport.len()).contains(&header_length) {
                return None;
            }
            Some(Ipv6Probe::Tcp(TcpSignal {
                flags: transport[13],
                sequence: u32::from_be_bytes(transport[4..8].try_into().ok()?),
                acknowledgement: u32::from_be_bytes(transport[8..12].try_into().ok()?),
                source_port: read_port(0)?,
                destination_port: read_port(2)?,
                complete: true,
            }))
        }
        17 if transport.len() == 8 && transport[4..6] == [0, 8] => {
            Some(Ipv6Probe::EmptyUdp(read_port(2)?))
        }
        58 if transport.len() >= 8 && transport[..2] == [128, 0] => Some(Ipv6Probe::EchoRequest),
        _ => None,
    }
}

pub(super) fn parse_ipv6_tcp_frame(raw: &[u8]) -> Option<TcpFrame<'_>> {
    let packet = parse_ipv6_inspection(raw)?;
    if packet.next_header != 6 || packet.fragmented || packet.extension_count > 32 {
        return None;
    }
    parse_tcp_transport(
        packet.transport,
        packet.declared_transport_len,
        Ipv6Addr::from(packet.source).into(),
        Ipv6Addr::from(packet.destination).into(),
    )
}

pub(super) fn is_ipv6_link_local(address: &[u8; 16]) -> bool {
    address[0] == 0xfe && address[1] & 0xc0 == 0x80
}

pub(super) fn ethernet_source_mac(raw: &[u8]) -> Option<[u8; 6]> {
    raw.get(6..12)?.try_into().ok()
}

pub(super) fn ndp_target_link_layer_address(mut options: &[u8]) -> Option<[u8; 6]> {
    let mut mac = None;
    while !options.is_empty() {
        let option_type = *options.first()?;
        let option_len = usize::from(*options.get(1)?) * 8;
        if option_len == 0 || option_len > options.len() {
            return None;
        }
        if option_type == 2 {
            if option_len != 8 || mac.is_some() {
                return None;
            }
            let address: [u8; 6] = options[2..8].try_into().ok()?;
            if address == [0; 6] || address[0] & 1 != 0 {
                return None;
            }
            mac = Some(address);
        }
        options = &options[option_len..];
    }
    mac
}

pub(super) fn ndp_options_well_formed(mut options: &[u8]) -> bool {
    while !options.is_empty() {
        let Some(&units) = options.get(1) else { return false };
        if units == 0 { return false; }
        let Some(rest) = options.get(usize::from(units) * 8..) else { return false };
        options = rest;
    }
    true
}

pub(super) fn ndp_message_name(data: &[u8]) -> Option<&'static str> {
    let (name, header_len) = match *data.first_chunk::<2>()? {
        [133, 0] => ("Router Solicitation", 8),
        [134, 0] => ("Router Advertisement", 16),
        [135, 0] => ("Neighbor Solicitation", 24),
        [136, 0] => ("Neighbor Advertisement", 24),
        [137, 0] => ("Redirect", 40),
        _ => return None,
    };
    ndp_options_well_formed(data.get(header_len..)?).then_some(name)
}

pub(super) fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub(super) fn stp_topology_indication(raw: &[u8]) -> Option<&'static str> {
    if raw.get(..6)? != [0x01, 0x80, 0xc2, 0, 0, 0] { return None; }
    let (offset, length) = ethernet_network_header(raw)?;
    if !(7..=1500).contains(&length) { return None; }
    let bpdu = raw.get(offset..offset + usize::from(length))?.strip_prefix(&[0x42, 0x42, 0x03, 0, 0])?;
    let &[version, kind] = bpdu.first_chunk::<2>()?;
    let body = &bpdu[2..];
    if (version, kind) == (0, 0x80) && body.is_empty() {
        return Some("STP topology-change notification");
    }
    // Bit 7 is an acknowledgement in classic STP, not a new notification.
    if *body.first()? & 1 == 0 { return None; }
    match (version, kind) {
        (0, 0) if bpdu.len() == 33 => Some("STP configuration topology-change flag"),
        (2, 2) if bpdu.len() == 34 && bpdu[33] == 0 => Some("RSTP topology-change flag"),
        (3, 2) if bpdu.get(33) == Some(&0) => {
            let extra = usize::from(u16::from_be_bytes(bpdu.get(34..36)?.try_into().ok()?));
            ((64..=64 + 64 * 16).contains(&extra) && (extra - 64) % 16 == 0
                && bpdu.len() == 36 + extra).then_some("MSTP common-tree topology-change flag")
        }
        _ => None,
    }
}

pub(super) struct LldpAdvertisement<'a> {
    pub(super) source: [u8; 6],
    pub(super) destination: [u8; 6],
    pub(super) chassis: &'a [u8],
    pub(super) port: &'a [u8],
    pub(super) ttl: u16,
}

fn lldp_tlv<'a>(remaining: &mut &'a [u8]) -> Option<(u16, &'a [u8])> {
    let header = u16::from_be_bytes(*remaining.first_chunk::<2>()?);
    let (value, rest) = remaining.get(2..)?.split_at_checked(usize::from(header & 0x01ff))?;
    *remaining = rest;
    Some((header >> 9, value))
}

pub(super) fn lldp_advertisement(raw: &[u8]) -> Option<LldpAdvertisement<'_>> {
    let (payload_offset, ether_type) = ethernet_network_header(raw)?;
    if ether_type != 0x88cc {
        return None;
    }
    let source = ethernet_source_mac(raw)?;
    let destination = *raw.first_chunk::<6>()?;
    if source == [0; 6] || source[0] & 1 != 0
        || !matches!(destination, [1, 0x80, 0xc2, 0, 0, 0 | 3 | 0x0e])
    {
        return None;
    }
    let mut remaining = raw.get(payload_offset..)?;
    let (1, chassis) = lldp_tlv(&mut remaining)? else { return None };
    let (2, port) = lldp_tlv(&mut remaining)? else { return None };
    let (3, ttl) = lldp_tlv(&mut remaining)? else { return None };
    if [chassis, port].iter().any(|id| !(2..=256).contains(&id.len()) || !matches!(id[0], 1..=7)) {
        return None;
    }
    let ttl = u16::from_be_bytes(ttl.try_into().ok()?);
    loop {
        match lldp_tlv(&mut remaining)? {
            (0, []) => return Some(LldpAdvertisement { source, destination, chassis, port, ttl }),
            (0..=3, _) => return None,
            _ => {}
        }
    }
}
