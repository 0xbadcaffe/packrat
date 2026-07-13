//! Structured packet fields for keyboard-driven investigation.

use crate::net::packet::Packet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketField {
    pub layer: String,
    pub path: String,
    pub label: String,
    pub value: String,
    pub offset: Option<usize>,
    pub length: Option<usize>,
}

impl PacketField {
    fn new(
        layer: &str,
        path: &str,
        label: &str,
        value: impl Into<String>,
        offset: Option<usize>,
        length: Option<usize>,
    ) -> Self {
        Self {
            layer: layer.into(),
            path: path.into(),
            label: label.into(),
            value: value.into(),
            offset,
            length,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct EtherLayout {
    ether_type_offset: usize,
    payload_offset: usize,
    ether_type: u16,
    vlan_tags: usize,
}

#[derive(Debug, Clone, Copy)]
struct TransportLayout {
    protocol: u8,
    offset: usize,
    payload_offset: usize,
}

pub fn extract_fields(packet: &Packet) -> Vec<PacketField> {
    let mut fields = vec![
        PacketField::new("Frame", "frame.number", "Frame Number", packet.no.to_string(), None, None),
        PacketField::new("Frame", "frame.time", "Relative Time", format!("{:.6}s", packet.timestamp), None, None),
        PacketField::new("Frame", "frame.len", "Frame Length", packet.length.to_string(), None, None),
        PacketField::new("Frame", "proto", "Protocol", packet.protocol.clone(), None, None),
    ];

    let bytes = packet.bytes.as_slice();
    if let Some(eth) = ethernet_layout(bytes) {
        fields.push(PacketField::new("Ethernet", "eth.dst", "Destination MAC", mac(bytes, 0), Some(0), Some(6)));
        fields.push(PacketField::new("Ethernet", "eth.src", "Source MAC", mac(bytes, 6), Some(6), Some(6)));
        fields.push(PacketField::new("Ethernet", "eth.type", "EtherType", format!("0x{:04x}", eth.ether_type), Some(eth.ether_type_offset), Some(2)));

        add_vlan_fields(packet, bytes, eth.vlan_tags, &mut fields);

        match eth.ether_type {
            0x0800 => add_ipv4_fields(bytes, eth.payload_offset, &mut fields),
            0x86dd => add_ipv6_fields(bytes, eth.payload_offset, &mut fields),
            _ => {}
        }

        if let Some(transport) = transport_layout(bytes, eth) {
            match transport.protocol {
                6 => add_tcp_fields(bytes, transport.offset, &mut fields),
                17 => add_udp_fields(bytes, transport.offset, &mut fields),
                _ => {}
            }
            add_tls_fields(bytes, transport.payload_offset, &mut fields);
            add_dtls_fields(bytes, transport.payload_offset, &mut fields);
        }
    } else {
        fields.push(PacketField::new("Bytes", "payload.len", "Captured Bytes", bytes.len().to_string(), None, None));
    }

    fields
}

pub fn filter_fields(fields: &[PacketField], query: &str) -> Vec<PacketField> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return fields.to_vec();
    }
    fields.iter()
        .filter(|field| {
            field.path.to_lowercase().contains(&q)
                || field.label.to_lowercase().contains(&q)
                || field.value.to_lowercase().contains(&q)
                || field.layer.to_lowercase().contains(&q)
        })
        .cloned()
        .collect()
}

pub fn filter_expression(field: &PacketField) -> Option<String> {
    match field.path.as_str() {
        "ip.src" | "ip.dst" | "ipv6.src" | "ipv6.dst" => Some(format!("{} == \"{}\"", field.path, field.value)),
        "proto" => Some(field.value.to_lowercase()),
        "frame.len" | "frame.number" | "ip.ttl" | "vlan.id" | "vlan.pcp" | "vlan.dei" => {
            Some(format!("{} == {}", field.path, field.value))
        }
        "tcp.srcport" | "tcp.dstport" | "udp.srcport" | "udp.dstport" => {
            Some(format!("{} == {}", field.path, field.value))
        }
        _ => None,
    }
}

fn ethernet_layout(bytes: &[u8]) -> Option<EtherLayout> {
    if bytes.len() < 14 {
        return None;
    }
    let mut ether_type_offset = 12;
    let mut ether_type = read_u16(bytes, ether_type_offset)?;
    let mut vlan_tags = 0;
    while matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
        if bytes.len() < ether_type_offset + 6 {
            return None;
        }
        vlan_tags += 1;
        ether_type_offset += 4;
        ether_type = read_u16(bytes, ether_type_offset)?;
    }
    Some(EtherLayout {
        ether_type_offset,
        payload_offset: ether_type_offset + 2,
        ether_type,
        vlan_tags,
    })
}

fn add_vlan_fields(packet: &Packet, bytes: &[u8], vlan_tags: usize, fields: &mut Vec<PacketField>) {
    for tag_index in 0..vlan_tags {
        let tci_offset = 14 + tag_index * 4;
        let Some(tci) = read_u16(bytes, tci_offset) else { continue; };
        let layer = if tag_index == 0 && vlan_tags > 1 { "Outer VLAN" } else { "VLAN" };
        let prefix = if tag_index == 0 && vlan_tags > 1 { "vlan.outer" } else { "vlan" };
        fields.push(PacketField::new(layer, &format!("{prefix}.id"), "VLAN ID", (tci & 0x0fff).to_string(), Some(tci_offset), Some(2)));
        fields.push(PacketField::new(layer, &format!("{prefix}.pcp"), "Priority Code Point", ((tci >> 13) & 0x7).to_string(), Some(tci_offset), Some(1)));
        fields.push(PacketField::new(layer, &format!("{prefix}.dei"), "Drop Eligible", ((tci >> 12) & 0x1).to_string(), Some(tci_offset), Some(1)));
    }

    if vlan_tags == 0 {
        if let Some(id) = packet.vlan_id {
            fields.push(PacketField::new("VLAN", "vlan.id", "VLAN ID", id.to_string(), None, None));
        }
        if let Some(id) = packet.outer_vlan_id {
            fields.push(PacketField::new("Outer VLAN", "vlan.outer.id", "Outer VLAN ID", id.to_string(), None, None));
        }
    }
}

fn add_ipv4_fields(bytes: &[u8], ip: usize, fields: &mut Vec<PacketField>) {
    if bytes.len() < ip + 20 {
        return;
    }
    let version = bytes[ip] >> 4;
    let ihl = (bytes[ip] & 0x0f) * 4;
    fields.push(PacketField::new("IPv4", "ip.version", "Version", version.to_string(), Some(ip), Some(1)));
    fields.push(PacketField::new("IPv4", "ip.hdr_len", "Header Length", ihl.to_string(), Some(ip), Some(1)));
    if let Some(total_len) = read_u16(bytes, ip + 2) {
        fields.push(PacketField::new("IPv4", "ip.len", "Total Length", total_len.to_string(), Some(ip + 2), Some(2)));
    }
    if let Some(id) = read_u16(bytes, ip + 4) {
        fields.push(PacketField::new("IPv4", "ip.id", "Identification", format!("0x{id:04x}"), Some(ip + 4), Some(2)));
    }
    fields.push(PacketField::new("IPv4", "ip.ttl", "Time To Live", bytes[ip + 8].to_string(), Some(ip + 8), Some(1)));
    fields.push(PacketField::new("IPv4", "ip.proto", "Protocol Number", bytes[ip + 9].to_string(), Some(ip + 9), Some(1)));
    fields.push(PacketField::new("IPv4", "ip.src", "Source Address", ipv4(bytes, ip + 12), Some(ip + 12), Some(4)));
    fields.push(PacketField::new("IPv4", "ip.dst", "Destination Address", ipv4(bytes, ip + 16), Some(ip + 16), Some(4)));
}

fn add_ipv6_fields(bytes: &[u8], ip: usize, fields: &mut Vec<PacketField>) {
    if bytes.len() < ip + 40 {
        return;
    }
    fields.push(PacketField::new("IPv6", "ip.version", "Version", (bytes[ip] >> 4).to_string(), Some(ip), Some(1)));
    fields.push(PacketField::new("IPv6", "ipv6.payload_len", "Payload Length", read_u16(bytes, ip + 4).unwrap_or(0).to_string(), Some(ip + 4), Some(2)));
    fields.push(PacketField::new("IPv6", "ipv6.next_header", "Next Header", bytes[ip + 6].to_string(), Some(ip + 6), Some(1)));
    fields.push(PacketField::new("IPv6", "ipv6.hop_limit", "Hop Limit", bytes[ip + 7].to_string(), Some(ip + 7), Some(1)));
    fields.push(PacketField::new("IPv6", "ipv6.src", "Source Address", ipv6(bytes, ip + 8), Some(ip + 8), Some(16)));
    fields.push(PacketField::new("IPv6", "ipv6.dst", "Destination Address", ipv6(bytes, ip + 24), Some(ip + 24), Some(16)));
}

fn transport_layout(bytes: &[u8], eth: EtherLayout) -> Option<TransportLayout> {
    match eth.ether_type {
        0x0800 => {
            let ip = eth.payload_offset;
            if bytes.len() < ip + 20 {
                return None;
            }
            let ihl = ((bytes[ip] & 0x0f) as usize) * 4;
            let offset = ip + ihl;
            let protocol = bytes[ip + 9];
            let payload_offset = match protocol {
                6 if bytes.len() >= offset + 20 => offset + (((bytes[offset + 12] >> 4) as usize) * 4),
                17 if bytes.len() >= offset + 8 => offset + 8,
                _ => offset,
            };
            Some(TransportLayout { protocol, offset, payload_offset })
        }
        0x86dd => {
            let ip = eth.payload_offset;
            if bytes.len() < ip + 40 {
                return None;
            }
            let offset = ip + 40;
            let protocol = bytes[ip + 6];
            let payload_offset = match protocol {
                6 if bytes.len() >= offset + 20 => offset + (((bytes[offset + 12] >> 4) as usize) * 4),
                17 if bytes.len() >= offset + 8 => offset + 8,
                _ => offset,
            };
            Some(TransportLayout { protocol, offset, payload_offset })
        }
        _ => None,
    }
}

fn add_tcp_fields(bytes: &[u8], tcp: usize, fields: &mut Vec<PacketField>) {
    if bytes.len() < tcp + 20 {
        return;
    }
    fields.push(PacketField::new("TCP", "tcp.srcport", "Source Port", read_u16(bytes, tcp).unwrap_or(0).to_string(), Some(tcp), Some(2)));
    fields.push(PacketField::new("TCP", "tcp.dstport", "Destination Port", read_u16(bytes, tcp + 2).unwrap_or(0).to_string(), Some(tcp + 2), Some(2)));
    fields.push(PacketField::new("TCP", "tcp.seq", "Sequence Number", read_u32(bytes, tcp + 4).unwrap_or(0).to_string(), Some(tcp + 4), Some(4)));
    fields.push(PacketField::new("TCP", "tcp.ack", "Acknowledgment Number", read_u32(bytes, tcp + 8).unwrap_or(0).to_string(), Some(tcp + 8), Some(4)));
    fields.push(PacketField::new("TCP", "tcp.hdr_len", "Header Length", (((bytes[tcp + 12] >> 4) as usize) * 4).to_string(), Some(tcp + 12), Some(1)));
    fields.push(PacketField::new("TCP", "tcp.flags", "Flags", format!("0x{:02x}", bytes[tcp + 13]), Some(tcp + 13), Some(1)));
    fields.push(PacketField::new("TCP", "tcp.window_size", "Window Size", read_u16(bytes, tcp + 14).unwrap_or(0).to_string(), Some(tcp + 14), Some(2)));
}

fn add_udp_fields(bytes: &[u8], udp: usize, fields: &mut Vec<PacketField>) {
    if bytes.len() < udp + 8 {
        return;
    }
    fields.push(PacketField::new("UDP", "udp.srcport", "Source Port", read_u16(bytes, udp).unwrap_or(0).to_string(), Some(udp), Some(2)));
    fields.push(PacketField::new("UDP", "udp.dstport", "Destination Port", read_u16(bytes, udp + 2).unwrap_or(0).to_string(), Some(udp + 2), Some(2)));
    fields.push(PacketField::new("UDP", "udp.length", "Length", read_u16(bytes, udp + 4).unwrap_or(0).to_string(), Some(udp + 4), Some(2)));
    fields.push(PacketField::new("UDP", "udp.checksum", "Checksum", format!("0x{:04x}", read_u16(bytes, udp + 6).unwrap_or(0)), Some(udp + 6), Some(2)));
}

fn add_tls_fields(bytes: &[u8], offset: usize, fields: &mut Vec<PacketField>) {
    if bytes.len() < offset + 5 || !matches!(bytes[offset], 20 | 21 | 22 | 23) || bytes[offset + 1] != 0x03 {
        return;
    }
    fields.push(PacketField::new("TLS", "tls.record.content_type", "Record Content Type", tls_content_type(bytes[offset]).to_string(), Some(offset), Some(1)));
    fields.push(PacketField::new("TLS", "tls.record.version", "Record Version", format!("0x{:02x}{:02x}", bytes[offset + 1], bytes[offset + 2]), Some(offset + 1), Some(2)));
    fields.push(PacketField::new("TLS", "tls.record.length", "Record Length", read_u16(bytes, offset + 3).unwrap_or(0).to_string(), Some(offset + 3), Some(2)));
}

fn add_dtls_fields(bytes: &[u8], offset: usize, fields: &mut Vec<PacketField>) {
    if bytes.len() < offset + 13 || !matches!(bytes[offset], 20 | 21 | 22 | 23) || bytes[offset + 1] != 0xfe {
        return;
    }
    fields.push(PacketField::new("DTLS", "dtls.record.content_type", "Record Content Type", tls_content_type(bytes[offset]).to_string(), Some(offset), Some(1)));
    fields.push(PacketField::new("DTLS", "dtls.record.version", "Record Version", format!("0x{:02x}{:02x}", bytes[offset + 1], bytes[offset + 2]), Some(offset + 1), Some(2)));
    fields.push(PacketField::new("DTLS", "dtls.record.epoch", "Epoch", read_u16(bytes, offset + 3).unwrap_or(0).to_string(), Some(offset + 3), Some(2)));
    fields.push(PacketField::new("DTLS", "dtls.record.sequence_number", "Sequence Number", read_u48(bytes, offset + 5).unwrap_or(0).to_string(), Some(offset + 5), Some(6)));
    fields.push(PacketField::new("DTLS", "dtls.record.length", "Record Length", read_u16(bytes, offset + 11).unwrap_or(0).to_string(), Some(offset + 11), Some(2)));
}

fn tls_content_type(value: u8) -> &'static str {
    match value {
        20 => "change_cipher_spec",
        21 => "alert",
        22 => "handshake",
        23 => "application_data",
        _ => "unknown",
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*bytes.get(offset)?, *bytes.get(offset + 1)?]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
    ]))
}

fn read_u48(bytes: &[u8], offset: usize) -> Option<u64> {
    let mut value = 0u64;
    for index in 0..6 {
        value = (value << 8) | (*bytes.get(offset + index)? as u64);
    }
    Some(value)
}

fn mac(bytes: &[u8], offset: usize) -> String {
    if bytes.len() < offset + 6 {
        return String::new();
    }
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
    )
}

fn ipv4(bytes: &[u8], offset: usize) -> String {
    if bytes.len() < offset + 4 {
        return String::new();
    }
    format!("{}.{}.{}.{}", bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3])
}

fn ipv6(bytes: &[u8], offset: usize) -> String {
    if bytes.len() < offset + 16 {
        return String::new();
    }
    bytes[offset..offset + 16]
        .chunks(2)
        .map(|chunk| format!("{:02x}{:02x}", chunk[0], chunk[1]))
        .collect::<Vec<_>>()
        .join(":")
}
