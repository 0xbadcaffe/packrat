//! TCP stream reassembly — reconstruct bidirectional byte streams from packets.

use std::collections::HashMap;
use crate::net::packet::Packet;

// ─── Transport helper ─────────────────────────────────────────────────────────

/// Returns true for any protocol that rides over TCP.
/// Used to decide whether to attempt stream reassembly.
pub fn is_tcp_transport(proto: &str) -> bool {
    matches!(proto,
        "TCP" | "HTTP" | "HTTPS" | "TLS" | "SSH" | "SMTP" | "MySQL" | "Redis"
        | "PostgreSQL" | "IMAP" | "IMAPS" | "POP3" | "MongoDB" | "Elasticsearch"
        | "Modbus" | "MQTT" | "MQTT-TLS" | "OPC-UA" | "DNP3" | "S7comm"
        | "EtherNet/IP" | "IEC-104" | "SIP" | "SIPS" | "BGP" | "FTP"
        | "Telnet" | "LDAP" | "DoIP" | "SOME/IP" | "SMB" | "RDP" | "Kerberos"
        | "NetBIOS-SSN" | "RTSP" | "Kafka" | "AMQP" | "NATS" | "Memcached"
        | "VNC" | "Docker" | "Prometheus" | "etcd"
    )
}

/// Compute the byte offset where the TCP payload begins, reading IHL and the
/// TCP data-offset field from the raw frame rather than assuming fixed headers.
pub fn tcp_payload_offset(pkt: &Packet) -> usize {
    let raw = &pkt.bytes;
    let eth_extra = if pkt.vlan_id.is_some() { 4 } else { 0 };
    let ip_off  = 14 + eth_extra;
    // IP header length from IHL nibble (lower 4 bits of first IP byte)
    let ihl = (raw.get(ip_off).copied().unwrap_or(0x45) & 0x0F) as usize * 4;
    let tp_off  = ip_off + ihl.max(20);
    // TCP header length from data-offset nibble (upper 4 bits of byte 12)
    let tcp_hdr = (raw.get(tp_off + 12).copied().unwrap_or(0x50) >> 4) as usize * 4;
    tp_off + tcp_hdr.max(20)
}

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
        if !is_tcp_transport(&pkt.protocol) { return None; }
        let sport = pkt.src_port?;
        let dport = pkt.dst_port?;
        let a = format!("{}:{}", pkt.src, sport);
        let b = format!("{}:{}", pkt.dst, dport);
        // canonical order — always ep_a < ep_b lexicographically
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
    /// Bytes from the A-side (first endpoint, client).
    pub client_data:   Vec<u8>,
    /// Bytes from the B-side (server).
    pub server_data:   Vec<u8>,
    pub client_pkts:   u32,
    pub server_pkts:   u32,
    pub first_seen:    f64,
    pub last_seen:     f64,
    pub closed:        bool,
    /// Combined interleaved segment metadata.
    pub segments:      Vec<StreamSegment>,
    /// Next expected TCP sequence number for each direction.
    /// None = not yet seen any data (no SYN or data packet yet).
    client_next_seq:   Option<u32>,
    server_next_seq:   Option<u32>,
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

const MAX_STREAMS:      usize = 500;
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

        // Evict oldest stream if at cap
        if !self.streams.contains_key(&id) && self.streams.len() >= MAX_STREAMS {
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

        // Read TCP flags and sequence number from raw bytes
        let raw = &pkt.bytes;
        let eth_extra = if pkt.vlan_id.is_some() { 4 } else { 0 };
        let ip_off  = 14 + eth_extra;
        let ihl     = (raw.get(ip_off).copied().unwrap_or(0x45) & 0x0F) as usize * 4;
        let tp_off  = ip_off + ihl.max(20);

        let tcp_flags = raw.get(tp_off + 13).copied().unwrap_or(0);
        let is_syn    = tcp_flags & 0x02 != 0;
        let is_fin    = tcp_flags & 0x01 != 0;
        let is_rst    = tcp_flags & 0x04 != 0;

        let tcp_seq: u32 = u32::from_be_bytes([
            raw.get(tp_off + 4).copied().unwrap_or(0),
            raw.get(tp_off + 5).copied().unwrap_or(0),
            raw.get(tp_off + 6).copied().unwrap_or(0),
            raw.get(tp_off + 7).copied().unwrap_or(0),
        ]);

        // Extract payload using the correctly computed offset
        let payload_start = tcp_payload_offset(pkt).min(raw.len());
        let payload = &raw[payload_start..];

        if is_rst {
            stream.closed = true;
            return;
        }

        // ── Sequence-number–aware assembly ─────────────────────────────────
        // We track the next expected sequence number per direction to:
        //   a) detect and skip retransmitted bytes
        //   b) detect gaps (out-of-order delivery) and still append best-effort
        //
        // Full out-of-order reorder buffering is not implemented; segments that
        // arrive out of order are appended immediately so the stream view is
        // still useful even if it may show data slightly out of sequence.

        let (data, next_seq_slot) = if from_client {
            (&mut stream.client_data, &mut stream.client_next_seq)
        } else {
            (&mut stream.server_data, &mut stream.server_next_seq)
        };

        // SYN without payload: initialise ISN, consume one sequence number
        if is_syn && payload.is_empty() {
            *next_seq_slot = Some(tcp_seq.wrapping_add(1));
            if from_client { stream.client_pkts += 1; } else { stream.server_pkts += 1; }
            return;
        }

        if payload.is_empty() {
            // Pure ACK or FIN with no payload
            if is_fin { *next_seq_slot = next_seq_slot.map(|s| s.wrapping_add(1)); stream.closed = true; }
            return;
        }

        // Determine how many of these bytes are new
        let new_payload: &[u8] = match *next_seq_slot {
            None => {
                // No SYN seen — start tracking from this packet
                *next_seq_slot = Some(tcp_seq.wrapping_add(payload.len() as u32)
                    .wrapping_add(if is_fin { 1 } else { 0 }));
                payload
            }
            Some(expected) => {
                // How far ahead of expected is this segment's start?
                // Using wrapping subtraction: positive = ahead, negative (large u32) = retransmit
                let delta = tcp_seq.wrapping_sub(expected) as i32;
                if delta >= 0 {
                    // In-order or gap (out-of-order): append the whole payload
                    let new_end = tcp_seq.wrapping_add(payload.len() as u32)
                        .wrapping_add(if is_fin { 1 } else { 0 });
                    // Advance next_seq to the furthest seen
                    if (new_end.wrapping_sub(expected)) as i32 > 0 {
                        *next_seq_slot = Some(new_end);
                    }
                    payload
                } else {
                    // Retransmit: how many bytes are already accounted for?
                    let already_seen = (-delta) as usize;
                    if already_seen >= payload.len() {
                        return; // pure retransmit, nothing new
                    }
                    let new_end = tcp_seq.wrapping_add(payload.len() as u32)
                        .wrapping_add(if is_fin { 1 } else { 0 });
                    if (new_end.wrapping_sub(expected)) as i32 > 0 {
                        *next_seq_slot = Some(new_end);
                    }
                    &payload[already_seen..]
                }
            }
        };

        if new_payload.is_empty() { return; }

        let seg = StreamSegment {
            from_client,
            offset:    data.len(),
            length:    new_payload.len(),
            timestamp: pkt.timestamp,
        };

        if data.len() < MAX_STREAM_BYTES {
            let space = MAX_STREAM_BYTES - data.len();
            data.extend_from_slice(&new_payload[..new_payload.len().min(space)]);
        }

        if from_client { stream.client_pkts += 1; } else { stream.server_pkts += 1; }

        if is_fin { stream.closed = true; }

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
