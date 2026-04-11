//! TCP stream reassembly — reconstruct bidirectional byte streams from packets.

use std::collections::HashMap;
use crate::net::packet::Packet;

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
        if pkt.protocol != "TCP" { return None; }
        let sport = pkt.src_port?;
        let dport = pkt.dst_port?;
        let a = format!("{}:{}", pkt.src, sport);
        let b = format!("{}:{}", pkt.dst, dport);
        // canonical order
        let (ep_a, ep_b) = if a < b { (a, b) } else { (b, a) };
        Some(StreamKey { ep_a, ep_b, proto: "TCP".into() })
    }

    pub fn id(&self) -> String {
        format!("{}-{}", self.ep_a, self.ep_b)
    }
}

// ─── Reassembled stream ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct ReassembledStream {
    pub key:           StreamKey,
    /// Bytes from the A-side (first endpoint).
    pub client_data:   Vec<u8>,
    /// Bytes from the B-side.
    pub server_data:   Vec<u8>,
    pub client_pkts:   u32,
    pub server_pkts:   u32,
    pub first_seen:    f64,
    pub last_seen:     f64,
    pub closed:        bool,
    /// Combined interleaved view with direction markers.
    pub segments:      Vec<StreamSegment>,
}

impl ReassembledStream {
    fn new(key: StreamKey, ts: f64) -> Self {
        Self { key, first_seen: ts, last_seen: ts, ..Default::default() }
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
    pub offset:      usize,
    pub length:      usize,
    pub timestamp:   f64,
}

impl Default for StreamKey {
    fn default() -> Self {
        Self { ep_a: String::new(), ep_b: String::new(), proto: String::new() }
    }
}

// ─── Assembler ────────────────────────────────────────────────────────────────

const MAX_STREAMS:     usize = 500;
const MAX_STREAM_BYTES: usize = 1_000_000; // 1 MB per direction

#[derive(Debug, Default)]
pub struct StreamAssembler {
    streams: HashMap<String, ReassembledStream>,
}

impl StreamAssembler {
    pub fn ingest(&mut self, pkt: &Packet) {
        let key = match StreamKey::from_packet(pkt) {
            Some(k) => k,
            None => return,
        };
        let id = key.id();

        // Evict oldest if at cap
        if !self.streams.contains_key(&id) && self.streams.len() >= MAX_STREAMS {
            // remove the stream with the oldest last_seen
            if let Some(oldest_id) = self.streams.iter()
                .min_by(|a, b| a.1.last_seen.partial_cmp(&b.1.last_seen).unwrap())
                .map(|(k, _)| k.clone())
            {
                self.streams.remove(&oldest_id);
            }
        }

        let stream = self.streams.entry(id)
            .or_insert_with(|| ReassembledStream::new(key.clone(), pkt.timestamp));
        stream.last_seen = pkt.timestamp.max(stream.last_seen);

        // Determine direction: is pkt.src the A-side?
        let sport = pkt.src_port.unwrap_or(0);
        let ep_a_ip_port = format!("{}:{}", pkt.src, sport);
        let from_client = ep_a_ip_port == stream.key.ep_a;

        // Extract payload (skip L2+L3+L4 headers; approximate at 54 bytes for Eth+IP+TCP)
        let payload_offset = 54.min(pkt.bytes.len());
        let payload = &pkt.bytes[payload_offset..];
        if payload.is_empty() { return; }

        let seg = StreamSegment {
            from_client,
            offset:    if from_client { stream.client_data.len() } else { stream.server_data.len() },
            length:    payload.len(),
            timestamp: pkt.timestamp,
        };

        if from_client {
            if stream.client_data.len() < MAX_STREAM_BYTES {
                stream.client_data.extend_from_slice(payload);
                stream.client_pkts += 1;
            }
        } else {
            if stream.server_data.len() < MAX_STREAM_BYTES {
                stream.server_data.extend_from_slice(payload);
                stream.server_pkts += 1;
            }
        }

        // Detect FIN/RST in TCP flags (byte 47 in Ethernet frame)
        if pkt.bytes.len() > 47 {
            let flags = pkt.bytes[47];
            if flags & 0x01 != 0 || flags & 0x04 != 0 { // FIN or RST
                stream.closed = true;
            }
        }

        stream.segments.push(seg);
    }

    pub fn get(&self, id: &str) -> Option<&ReassembledStream> { self.streams.get(id) }

    pub fn all(&self) -> Vec<&ReassembledStream> {
        let mut v: Vec<_> = self.streams.values().collect();
        v.sort_by(|a, b| b.last_seen.partial_cmp(&a.last_seen).unwrap_or(std::cmp::Ordering::Equal));
        v
    }

    pub fn len(&self) -> usize { self.streams.len() }
    pub fn is_empty(&self) -> bool { self.streams.is_empty() }

    pub fn clear(&mut self) { self.streams.clear(); }
}

fn printable_preview(data: &[u8], max: usize) -> String {
    let slice = &data[..data.len().min(max)];
    slice.iter().map(|&b| {
        if b == b'\r' { return '↵';  }
        if b == b'\n' { return '↵'; }
        if b.is_ascii_graphic() || b == b' ' { b as char } else { '·' }
    }).collect()
}
