use crate::net::packet::Packet;

/// Display filter applied to the packet stream.
#[derive(Default)]
pub struct PacketFilter {
    pub input: String,
    pub active: bool, // editing mode
}

impl PacketFilter {
    pub fn matches(&self, p: &Packet) -> bool {
        let f = self.input.trim().to_lowercase();
        if f.is_empty() {
            return true;
        }
        if let Some(ip) = f.strip_prefix("ip.src==") {
            return p.src == ip;
        }
        if let Some(ip) = f.strip_prefix("ip.dst==") {
            return p.dst == ip;
        }
        if let Some(port) = f.strip_prefix("tcp.port==") {
            return p.src_port.map(|x| x.to_string()).as_deref() == Some(port)
                || p.dst_port.map(|x| x.to_string()).as_deref() == Some(port);
        }
        if let Some(vlan) = f.strip_prefix("vlan==") {
            return p.vlan_id.map(|x| x.to_string()).as_deref() == Some(vlan);
        }
        p.protocol.to_lowercase().contains(&f)
            || p.src.contains(&f)
            || p.dst.contains(&f)
            || p.info.to_lowercase().contains(&f)
    }
}
