use super::{ethernet_layout, transport_layout, truncated_wire_end};
use crate::net::packet::Packet;

pub(crate) fn captured_udp_payload(packet: &Packet) -> Option<&[u8]> {
    if packet.capture.as_ref().is_some_and(|capture| capture.link_type != 1) {
        return None;
    }
    let bytes = packet.bytes.as_slice();
    let ethernet = ethernet_layout(bytes)?;
    if ethernet.vlan_tags > 2 {
        return None;
    }
    let udp = transport_layout(bytes, ethernet, truncated_wire_end(packet))?;
    if udp.protocol != 17 || udp.fragmented {
        return None;
    }
    bytes.get(udp.payload_offset..udp.end)
}
