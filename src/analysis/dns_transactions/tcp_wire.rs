use crate::analysis::stream::{tcp_port_pair, tcp_segment_payload};
use crate::net::packet::Packet;

pub(super) fn dns_payload(packet: &Packet) -> Option<(u16, u16, &[u8])> {
    if packet.src_port != Some(53) && packet.dst_port != Some(53) {
        return None;
    }
    let (source, destination) = tcp_port_pair(packet)?;
    if source != 53 && destination != 53 {
        return None;
    }
    let (_, payload) = tcp_segment_payload(packet)?;
    let length = usize::from(u16::from_be_bytes(*payload.first_chunk::<2>()?));
    // A single packet observation needs an unambiguous message boundary.
    (length >= 12 && length + 2 == payload.len()).then(|| (source, destination, &payload[2..]))
}
