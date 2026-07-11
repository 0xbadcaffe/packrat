//! QUIC connection inventory from version-independent header fields.

use std::collections::{HashMap, HashSet};

use crate::analysis::encrypted_insight::parse_quic_header;
use crate::net::packet::Packet;

#[derive(Debug, Clone)]
pub struct QuicConnection {
    pub id: String,
    pub version: Option<u32>,
    pub destination_id: String,
    pub source_id: String,
    pub packet_types: HashSet<String>,
    pub addresses: HashSet<String>,
    pub packets: u64,
    pub bytes: u64,
    pub first_seen: f64,
    pub last_seen: f64,
    pub fixed_bit_valid: bool,
}

impl QuicConnection {
    pub fn migration_observed(&self) -> bool {
        self.addresses.len() > 2
    }
}

#[derive(Debug, Default)]
pub struct QuicScope {
    pub connections: HashMap<String, QuicConnection>,
}

impl QuicScope {
    pub fn ingest(&mut self, packet: &Packet) {
        if !packet.protocol.eq_ignore_ascii_case("QUIC") && packet.dst_port != Some(443) && packet.src_port != Some(443) {
            return;
        }
        let Some(header) = parse_quic_header(&packet.bytes) else { return; };
        let id = if !header.destination_id.is_empty() {
            header.destination_id.clone()
        } else {
            flow_id(packet)
        };
        let connection = self.connections.entry(id.clone()).or_insert_with(|| QuicConnection {
            id,
            version: header.version,
            destination_id: header.destination_id.clone(),
            source_id: header.source_id.clone(),
            packet_types: HashSet::new(),
            addresses: HashSet::new(),
            packets: 0,
            bytes: 0,
            first_seen: packet.timestamp,
            last_seen: packet.timestamp,
            fixed_bit_valid: header.fixed_bit,
        });
        connection.packet_types.insert(header.packet_type.into());
        connection.addresses.insert(packet.src.clone());
        connection.addresses.insert(packet.dst.clone());
        connection.packets += 1;
        connection.bytes += packet.length as u64;
        connection.last_seen = packet.timestamp;
        connection.fixed_bit_valid &= header.fixed_bit;
        if connection.version.is_none() { connection.version = header.version; }
        if connection.source_id.is_empty() { connection.source_id = header.source_id; }
    }

    pub fn all(&self) -> Vec<&QuicConnection> {
        let mut connections: Vec<_> = self.connections.values().collect();
        connections.sort_by(|left, right| right.last_seen.partial_cmp(&left.last_seen).unwrap_or(std::cmp::Ordering::Equal));
        connections
    }

    pub fn clear(&mut self) {
        self.connections.clear();
    }
}

fn flow_id(packet: &Packet) -> String {
    let left = format!("{}:{}", packet.src, packet.src_port.unwrap_or(0));
    let right = format!("{}:{}", packet.dst, packet.dst_port.unwrap_or(0));
    if left < right { format!("{left}-{right}") } else { format!("{right}-{left}") }
}
