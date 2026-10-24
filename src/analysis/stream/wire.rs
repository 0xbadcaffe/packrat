use crate::net::packet::Packet;

#[derive(Debug, Clone, Copy)]
pub(super) struct TcpView {
    pub header: usize,
    pub payload: usize,
    pub end: usize,
    pub truncated: bool,
}

pub fn tcp_payload_offset(packet: &Packet) -> usize {
    tcp_view(packet).map_or(packet.bytes.len(), |view| view.payload)
}

pub(super) fn tcp_view(packet: &Packet) -> Option<TcpView> {
    if packet
        .capture
        .as_ref()
        .is_some_and(|capture| capture.link_type != 1)
    {
        return None;
    }
    let raw = &packet.bytes;
    let mut ether_type = read_u16(raw, 12)?;
    let mut ip = 14usize;
    for _ in 0..2 {
        if !matches!(ether_type, 0x8100 | 0x88a8) {
            break;
        }
        ether_type = read_u16(raw, ip + 2)?;
        ip += 4;
    }
    let (header, declared_end) = match ether_type {
        0x0800 => {
            if raw.get(ip)? >> 4 != 4 {
                return None;
            }
            let length = usize::from(raw.get(ip)? & 0x0f) * 4;
            let total = usize::from(read_u16(raw, ip + 2)?);
            if length < 20
                || total < length
                || *raw.get(ip + 9)? != 6
                || read_u16(raw, ip + 6)? & 0x3fff != 0
            {
                return None;
            }
            (ip.checked_add(length)?, ip.checked_add(total)?)
        }
        0x86dd => {
            if raw.get(ip)? >> 4 != 6 {
                return None;
            }
            let length = usize::from(read_u16(raw, ip + 4)?);
            if length == 0 {
                return None;
            } // Jumbo Payload options are not decoded here.
            let end = ip.checked_add(40)?.checked_add(length)?;
            (ipv6_tcp_offset(raw, ip, end.min(raw.len()))?, end)
        }
        _ => return None,
    };
    let end = declared_end.min(raw.len());
    let length = usize::from(*raw.get(header + 12)? >> 4) * 4;
    let payload = header.checked_add(length)?;
    if length < 20 || payload > end {
        return None;
    }
    Some(TcpView {
        header,
        payload,
        end,
        truncated: raw.len() < declared_end,
    })
}

fn ipv6_tcp_offset(raw: &[u8], ip: usize, end: usize) -> Option<usize> {
    let mut next = *raw.get(ip + 6)?;
    let mut offset = ip.checked_add(40)?;
    for _ in 0..16 {
        if offset > end {
            return None;
        }
        let length = match next {
            6 => return Some(offset),
            0 | 43 | 60 => (usize::from(*raw.get(offset + 1)?) + 1) * 8,
            51 => (usize::from(*raw.get(offset + 1)?) + 2) * 4,
            44 => {
                if read_u16(raw, offset + 2)? & 0xfff9 != 0 {
                    return None;
                }
                8
            }
            _ => return None,
        };
        next = *raw.get(offset)?;
        offset = offset.checked_add(length)?;
    }
    None
}

fn read_u16(raw: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        raw.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}
