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
        })
    }

    pub fn id(&self) -> String {
        format!("{}-{}", self.ep_a, self.ep_b)
    }
}

// ─── Reassembled stream ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct ReassembledStream {
    pub key: StreamKey,
    /// Bytes from the A-side (first endpoint, client).
    pub client_data: Vec<u8>,
    /// Bytes from the B-side (server).
    pub server_data: Vec<u8>,
    pub client_pkts: u32,
    pub server_pkts: u32,
    pub first_seen: f64,
    pub last_seen: f64,
    pub closed: bool,
    /// Combined interleaved segment metadata.
    pub segments: Vec<StreamSegment>,
    /// Next expected TCP sequence number for each direction.
    /// None = not yet seen any data (no SYN or data packet yet).
    client_next_seq: Option<u32>,
    server_next_seq: Option<u32>,
    client_pending: Vec<PendingTcpSegment>,
    server_pending: Vec<PendingTcpSegment>,
}

impl ReassembledStream {
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
}

impl Default for StreamKey {
    fn default() -> Self {
        Self {
            ep_a: String::new(),
            ep_b: String::new(),
            proto: String::new(),
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
