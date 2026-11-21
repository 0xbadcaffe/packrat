use std::net::Ipv4Addr;

use crate::analysis::dns_transactions::{parse_name, udp_payload};
use crate::net::packet::Packet;

pub(super) fn wpad_address_reply(packet: &Packet) -> Option<(u16, Ipv4Addr, usize)> {
    let (source_port, _, payload) = udp_payload(packet)?;
    let header = payload.first_chunk::<12>()?;
    if source_port != 137 || header[2] & 0xfa != 0x80 || header[3] & 0x0f != 0
        || header[4..] != [0, 0, 0, 1, 0, 0, 0, 0]
    {
        return None;
    }
    let (name, offset) = parse_name(payload, 12)?;
    let label = name.split('.').next()?.as_bytes();
    if label.len() != 32 {
        return None;
    }
    let mut decoded = [0; 16];
    for (value, pair) in decoded.iter_mut().zip(label.chunks_exact(2)) {
        let [hi, lo] = [pair[0].checked_sub(b'a')?, pair[1].checked_sub(b'a')?];
        if hi > 15 || lo > 15 {
            return None;
        }
        *value = hi << 4 | lo;
    }
    if &decoded != b"WPAD           \0" {
        return None;
    }
    let record = payload.get(offset..offset + 10)?;
    if record[..4] != [0, 0x20, 0, 1] {
        return None;
    }
    let addresses = payload.get(offset + 10..)?;
    let length = usize::from(u16::from_be_bytes([record[8], record[9]]));
    if length != addresses.len() || length < 6 || length % 6 != 0 {
        return None;
    }
    let address = Ipv4Addr::from(<[u8; 4]>::try_from(&addresses[2..6]).ok()?);
    Some((u16::from_be_bytes([header[0], header[1]]), address, length / 6))
}
