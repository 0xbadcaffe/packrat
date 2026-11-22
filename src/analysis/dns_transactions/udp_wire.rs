use crate::net::packet::Packet;
use crate::net::parser::ethernet_network_header;

pub(crate) fn udp_payload(packet: &Packet) -> Option<(u16, u16, &[u8])> {
    let (ports, len, udp) = udp_view(packet)?;
    Some((ports.0, ports.1, udp.get(8..len)?))
}

pub(crate) fn udp_port_pair(packet: &Packet) -> Option<(u16, u16)> {
    udp_view(packet).map(|(ports, _, _)| ports)
}

fn udp_view(packet: &Packet) -> Option<((u16, u16), usize, &[u8])> {
    if packet
        .capture
        .as_ref()
        .is_some_and(|metadata| metadata.link_type != 1)
    {
        return None;
    }
    let raw = packet.bytes.as_slice();
    let (network, ether_type) = ethernet_network_header(raw)?;
    let (transport, network_end) = match ether_type {
        0x0800 if raw.get(network)? >> 4 == 4 && raw.get(network + 9) == Some(&17) => {
            let ihl = usize::from(raw.get(network)? & 0x0f) * 4;
            let fragment = u16::from_be_bytes(raw.get(network + 6..network + 8)?.try_into().ok()?);
            if ihl < 20 || fragment & 0x3fff != 0 {
                return None;
            }
            let length = u16::from_be_bytes(raw.get(network + 2..network + 4)?.try_into().ok()?);
            (network + ihl, network + usize::from(length))
        }
        0x86dd if raw.get(network)? >> 4 == 6 => {
            let length = u16::from_be_bytes(raw.get(network + 4..network + 6)?.try_into().ok()?);
            let end = network + 40 + usize::from(length);
            (ipv6_udp_offset(&raw[..end.min(raw.len())], network)?, end)
        }
        _ => return None,
    };
    let udp = raw.get(transport..network_end.min(raw.len()))?;
    let &[src_hi, src_lo, dst_hi, dst_lo, len_hi, len_lo, _, _] = udp.first_chunk::<8>()?;
    let udp_length = usize::from(u16::from_be_bytes([len_hi, len_lo]));
    if !(8..=network_end.checked_sub(transport)?).contains(&udp_length) {
        return None;
    }
    Some((
        (u16::from_be_bytes([src_hi, src_lo]), u16::from_be_bytes([dst_hi, dst_lo])),
        udp_length,
        udp,
    ))
}

fn ipv6_udp_offset(raw: &[u8], network: usize) -> Option<usize> {
    let mut next = *raw.get(network + 6)?;
    let mut cursor = network + 40;
    for _ in 0..16 {
        if next == 17 {
            return Some(cursor);
        }
        match next {
            0 | 43 | 60 => {
                next = *raw.get(cursor)?;
                cursor = cursor.checked_add(((*raw.get(cursor + 1)? as usize) + 1) * 8)?;
            }
            51 => {
                next = *raw.get(cursor)?;
                cursor = cursor.checked_add(((*raw.get(cursor + 1)? as usize) + 2) * 4)?;
            }
            _ => return None,
        }
    }
    None
}
