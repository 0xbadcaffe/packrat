//! TCP stream reassembly — reconstruct bidirectional byte streams from packets.

use crate::net::packet::Packet;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ─── Transport helper ─────────────────────────────────────────────────────────

/// Returns true for any protocol that rides over TCP.
/// Used to decide whether to attempt stream reassembly.
pub fn is_tcp_transport(proto: &str) -> bool {
    matches!(
        proto,
        "TCP"
            | "HTTP"
            | "HTTPS"
            | "TLS"
            | "SSH"
            | "SMTP"
            | "MySQL"
            | "Redis"
            | "PostgreSQL"
            | "IMAP"
            | "IMAPS"
            | "POP3"
            | "MongoDB"
            | "Elasticsearch"
            | "Modbus"
            | "MQTT"
            | "MQTT-TLS"
            | "OPC-UA"
            | "DNP3"
            | "S7comm"
            | "EtherNet/IP"
            | "IEC-104"
            | "SIP"
            | "SIPS"
            | "BGP"
            | "FTP"
            | "Telnet"
            | "LDAP"
            | "DoIP"
            | "SOME/IP"
            | "SMB"
            | "RDP"
            | "Kerberos"
            | "NetBIOS-SSN"
            | "RTSP"
            | "Kafka"
            | "AMQP"
            | "NATS"
            | "Memcached"
            | "VNC"
            | "Docker"
            | "Prometheus"
            | "etcd"
    )
}

mod assembler;
mod sequence;
mod tools;
mod wire;
pub use assembler::StreamAssembler;
use sequence::*;
pub use tools::{StreamMatch, StreamOverlayState, export_segments, search_segments};
pub use wire::tcp_payload_offset;
use wire::*;

// ─── Stream key ───────────────────────────────────────────────────────────────

/// Canonical bi-directional flow key (lower endpoint first).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub ep_a: String, // "ip:port"
    pub ep_b: String,
    pub proto: String,
    pub vlan_id: Option<u16>,
    pub outer_vlan_id: Option<u16>,
    pub interface: Option<String>,
    pub interface_id: u32,
    pub section: u32,
}

impl StreamKey {
    pub fn from_packet(pkt: &Packet) -> Option<Self> {
        if !is_tcp_transport(&pkt.protocol) {
            return None;
        }
        let sport = pkt.src_port?;
        let dport = pkt.dst_port?;
        let a = format!("{}:{}", pkt.src, sport);
        let b = format!("{}:{}", pkt.dst, dport);
        // canonical order — always ep_a < ep_b lexicographically
        let (ep_a, ep_b) = if a < b { (a, b) } else { (b, a) };
        Some(StreamKey {
            ep_a,
            ep_b,
            proto: "TCP".into(),
            vlan_id: pkt.vlan_id,
            outer_vlan_id: pkt.outer_vlan_id,
            interface: pkt
                .capture
                .as_ref()
                .and_then(|capture| capture.interface_name.clone()),
            interface_id: pkt
                .capture
                .as_ref()
                .map_or(0, |capture| capture.interface_id),
            section: pkt.capture.as_ref().map_or(0, |capture| capture.section_id),
        })
    }

    pub fn id(&self) -> String {
        if self.vlan_id.is_none()
            && self.outer_vlan_id.is_none()
            && self.interface.is_none()
            && self.section == 0
            && self.interface_id == 0
        {
            return format!("{}-{}", self.ep_a, self.ep_b);
        }
        let interface = self.interface.as_deref().unwrap_or("");
        format!(
            "{}-{}|{}:{}:{}:{}|{}|{:?}|{:?}",
            self.ep_a,
            self.ep_b,
            self.interface.is_some(),
            self.interface_id,
            interface.len(),
            interface,
            self.section,
            self.outer_vlan_id,
            self.vlan_id
        )
    }
}

// ─── Reassembled stream ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct ReassembledStream {
    pub key: StreamKey,
    /// Changes on every ingested segment, including FIN, RST, and gap fills.
    pub revision: u64,
    /// Bytes from canonical endpoint A (not necessarily the client).
    pub client_data: Vec<u8>,
    /// Bytes from canonical endpoint B (not necessarily the server).
    pub server_data: Vec<u8>,
    pub client_pkts: u32,
    pub server_pkts: u32,
    pub first_seen: f64,
    pub last_seen: f64,
    pub closed: bool,
    /// At least one contributing TCP segment has missing capture bytes.
    pub truncated: bool,
    pub reset: bool,
    pub client_finished: bool,
    pub server_finished: bool,
    pub client_fin_packet: Option<u64>,
    pub server_fin_packet: Option<u64>,
    pub midstream: bool,
    pub epoch_ambiguous: bool,
    pub dropped_segments: u64,
    pub provenance_truncated: bool,
    /// Combined interleaved segment metadata.
    pub segments: Vec<StreamSegment>,
    /// Next expected TCP sequence number for each direction.
    /// None = not yet seen any data (no SYN or data packet yet).
    client_next_seq: Option<u32>,
    server_next_seq: Option<u32>,
    client_pending: Vec<PendingTcpSegment>,
    server_pending: Vec<PendingTcpSegment>,
    client_initial_syn: Option<u32>,
    server_initial_syn: Option<u32>,
}

impl ReassembledStream {
    pub fn pending_segments(&self) -> usize {
        self.client_pending.len() + self.server_pending.len()
    }

    pub fn has_gaps(&self) -> bool {
        self.truncated
            || self.dropped_segments > 0
            || self.pending_segments() > 0
            || self.epoch_ambiguous
    }

    pub fn packet_numbers(&self, from_a: bool, start: usize, end: usize) -> Vec<u64> {
        self.segments
            .iter()
            .filter(|segment| {
                segment.from_client == from_a
                    && segment.offset < end
                    && segment.offset.saturating_add(segment.length) > start
            })
            .map(|segment| segment.packet_no)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    fn new(key: StreamKey, ts: f64) -> Self {
        Self {
            key,
            first_seen: ts,
            last_seen: ts,
            ..Default::default()
        }
    }

    /// Plain-text preview (first 256 bytes of each direction).
    pub fn preview(&self) -> String {
        let c = printable_preview(&self.client_data, 256);
        let s = printable_preview(&self.server_data, 256);
        format!("→ {c}\n← {s}")
    }

    /// Detect if stream looks like HTTP.
    pub fn is_http(&self) -> bool {
        self.client_data.starts_with(b"GET ")
            || self.client_data.starts_with(b"POST ")
            || self.client_data.starts_with(b"HTTP/")
            || self.server_data.starts_with(b"HTTP/")
    }
}

#[derive(Debug, Clone)]
pub struct StreamSegment {
    pub from_client: bool,
    pub offset: usize,
    pub length: usize,
    pub timestamp: f64,
    pub packet_no: u64,
}

impl Default for StreamKey {
    fn default() -> Self {
        Self {
            ep_a: String::new(),
            ep_b: String::new(),
            proto: String::new(),
            vlan_id: None,
            outer_vlan_id: None,
            interface: None,
            interface_id: 0,
            section: 0,
        }
    }
}

fn printable_preview(data: &[u8], max: usize) -> String {
    let slice = &data[..data.len().min(max)];
    slice
        .iter()
        .map(|&b| {
            if b == b'\r' {
                return '↵';
            }
            if b == b'\n' {
                return '↵';
            }
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '·'
            }
        })
        .collect()
}
