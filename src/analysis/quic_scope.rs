//! QUIC connection inventory from version-independent header fields.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use crate::analysis::encrypted_insight::parse_quic_header;
use crate::analysis::helper_process::JsonLineHelper;
use crate::analysis::transactions::http3::{AuthenticatedHttp3Batch, Http3Tracker};
use crate::net::packet::Packet;

#[derive(Debug, Clone, Default)]
pub struct QuicDecodedFrame {
    pub packet_no: u64,
    pub frame_type: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct QuicConnection {
    pub id: String,
    pub version: Option<u32>,
    pub destination_id: String,
    pub source_id: String,
    pub ratq: String,
    pub packet_types: HashSet<String>,
    pub addresses: HashSet<String>,
    pub addresses_truncated: bool,
    pub packets: u64,
    pub bytes: u64,
    pub first_seen: f64,
    pub last_seen: f64,
    pub fixed_bit_valid: bool,
    pub decoded_frames: Vec<QuicDecodedFrame>,
}

impl QuicConnection {
    pub fn migration_observed(&self) -> bool {
        self.addresses.len() > 2
    }
}

pub struct QuicScope {
    pub connections: HashMap<String, QuicConnection>,
    pub decode_helper_path: Option<PathBuf>,
    decode_helper: Option<JsonLineHelper>,
    pub http3: Http3Tracker,
    pub decode_errors: u64,
    pub last_decode_error: Option<String>,
    pub evicted_connections: u64,
    connection_order: VecDeque<String>,
}

impl Default for QuicScope {
    fn default() -> Self {
        Self {
            connections: HashMap::new(),
            decode_helper_path: None,
            decode_helper: None,
            http3: Http3Tracker::default(),
            decode_errors: 0,
            last_decode_error: None,
            evicted_connections: 0,
            connection_order: VecDeque::new(),
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct QuicDecodeRequest {
    connection_id: String,
    packet_no: u64,
    packet_hex: String,
}

#[derive(Debug, serde::Deserialize)]
struct QuicDecodeResponse {
    ok: bool,
    #[serde(default)]
    frames: Vec<QuicDecodeFrameResponse>,
    detail: Option<String>,
    #[serde(default)]
    http3: Option<AuthenticatedHttp3Batch>,
}

#[derive(Debug, serde::Deserialize)]
struct QuicDecodeFrameResponse {
    frame_type: String,
    detail: String,
}

impl QuicScope {
    pub fn ingest(&mut self, packet: &Packet) {
        if !packet.protocol.eq_ignore_ascii_case("QUIC")
            && packet.dst_port != Some(443)
            && packet.src_port != Some(443)
        {
            return;
        }
        let Some(header) = parse_quic_header(&packet.bytes) else {
            return;
        };
        let id = if !header.destination_id.is_empty() {
            header.destination_id.clone()
        } else {
            flow_id(packet)
        };
        if !self.connections.contains_key(&id) {
            while self.connections.len() >= 1024 {
                let Some(oldest) = self.connection_order.pop_front() else {
                    break;
                };
                if self.connections.remove(&oldest).is_some() {
                    self.evicted_connections = self.evicted_connections.saturating_add(1);
                }
            }
            self.connection_order.push_back(id.clone());
        }
        let connection = self
            .connections
            .entry(id.clone())
            .or_insert_with(|| QuicConnection {
                id,
                version: header.version,
                destination_id: header.destination_id.clone(),
                source_id: header.source_id.clone(),
                ratq: header.ratq.clone(),
                packet_types: HashSet::new(),
                addresses: HashSet::new(),
                addresses_truncated: false,
                packets: 0,
                bytes: 0,
                first_seen: packet.timestamp,
                last_seen: packet.timestamp,
                fixed_bit_valid: header.fixed_bit,
                decoded_frames: Vec::new(),
            });
        connection.packet_types.insert(header.packet_type.into());
        for address in [&packet.src, &packet.dst] {
            if connection.addresses.len() < 32 {
                connection.addresses.insert(address.clone());
            } else if !connection.addresses.contains(address) {
                connection.addresses_truncated = true;
            }
        }
        connection.packets += 1;
        connection.bytes += packet.length as u64;
        connection.last_seen = packet.timestamp;
        connection.fixed_bit_valid &= header.fixed_bit;
        if connection.version.is_none() {
            connection.version = header.version;
        }
        if connection.source_id.is_empty() {
            connection.source_id = header.source_id;
        }
        if connection.ratq.is_empty() {
            connection.ratq = header.ratq;
        }
        let connection_id = connection.id.clone();
        if let Some(mut frames) = self.decode_packet(&connection_id, packet.no, &packet.bytes) {
            if let Some(connection) = self.connections.get_mut(&connection_id) {
                connection.decoded_frames.append(&mut frames);
                if connection.decoded_frames.len() > 100 {
                    let excess = connection.decoded_frames.len() - 100;
                    connection.decoded_frames.drain(0..excess);
                }
            }
        }
    }

    pub fn all(&self) -> Vec<&QuicConnection> {
        let mut connections: Vec<_> = self.connections.values().collect();
        connections.sort_by(|left, right| {
            right
                .last_seen
                .partial_cmp(&left.last_seen)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        connections
    }

    pub fn clear(&mut self) {
        self.connections.clear();
        self.http3.clear();
        self.decode_helper = None;
        self.decode_errors = 0;
        self.last_decode_error = None;
        self.evicted_connections = 0;
        self.connection_order.clear();
    }

    fn decode_packet(
        &mut self,
        connection_id: &str,
        packet_no: u64,
        packet: &[u8],
    ) -> Option<Vec<QuicDecodedFrame>> {
        let helper = self.decode_helper_path.clone()?;
        if self
            .decode_helper
            .as_ref()
            .is_none_or(|running| running.program() != helper)
        {
            match JsonLineHelper::spawn(&helper, "QUIC decode") {
                Ok(process) => self.decode_helper = Some(process),
                Err(error) => {
                    self.decode_errors = self.decode_errors.saturating_add(1);
                    self.last_decode_error = Some(error.chars().take(512).collect());
                    return None;
                }
            }
        }
        let request = QuicDecodeRequest {
            connection_id: connection_id.to_string(),
            packet_no,
            packet_hex: hex(packet),
        };
        let result = self
            .decode_helper
            .as_mut()?
            .request::<_, QuicDecodeResponse>(&request)
            .and_then(|response| {
                let (frames, http3) = decode_quic_response(response, packet_no)?;
                if let Some(batch) = http3 {
                    self.http3.ingest_authenticated(batch, packet_no)?;
                }
                Ok(frames)
            });
        if let Err(error) = &result {
            self.decode_helper = None;
            self.decode_errors = self.decode_errors.saturating_add(1);
            self.last_decode_error = Some(error.chars().take(512).collect());
        }
        result.ok()
    }
}

fn flow_id(packet: &Packet) -> String {
    let left = format!("{}:{}", packet.src, packet.src_port.unwrap_or(0));
    let right = format!("{}:{}", packet.dst, packet.dst_port.unwrap_or(0));
    if left < right {
        format!("{left}-{right}")
    } else {
        format!("{right}-{left}")
    }
}

fn decode_quic_response(
    response: QuicDecodeResponse,
    packet_no: u64,
) -> Result<(Vec<QuicDecodedFrame>, Option<AuthenticatedHttp3Batch>), String> {
    if !response.ok {
        return Err(response
            .detail
            .unwrap_or_else(|| "QUIC decode helper did not authenticate packet".into()));
    }
    if response.frames.len() > 256
        || response
            .frames
            .iter()
            .any(|frame| frame.frame_type.len() > 64 || frame.detail.len() > 512)
    {
        return Err("QUIC decoded frame detail limit exceeded".into());
    }
    Ok((
        response
            .frames
            .into_iter()
            .map(|frame| QuicDecodedFrame {
                packet_no,
                frame_type: frame.frame_type,
                detail: frame.detail,
            })
            .collect(),
        response.http3,
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
#[path = "../../tests/unit/analysis_quic_scope_tests.rs"]
mod tests;
