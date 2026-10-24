//! Reconstruction from explicitly authenticated helper events, never ciphertext.
use super::{MAX_HEADER_BYTES, MAX_HEADERS};
use std::collections::BTreeMap;

mod model;
mod reconstruct;
mod state;
pub use model::*;
use state::{Connection, HalfStream};

const MAX_OFFSET: u64 = (1u64 << 62) - 1;
const MAX_CONNECTIONS: usize = 64;
const MAX_STREAMS: usize = 128;
const MAX_EVENTS: usize = 16_384;
const MAX_RETAINED_BYTES: usize = 16 * 1024 * 1024;

#[derive(Default)]
pub struct Http3Tracker {
    connections: BTreeMap<String, Connection>,
    retained_bytes: usize,
    retained_events: usize,
    pub rejected_batches: u64,
}

impl Http3Tracker {
    /// Call only on the success path of a configured, trusted decrypting helper.
    pub fn ingest_authenticated(
        &mut self,
        batch: AuthenticatedHttp3Batch,
        packet_no: u64,
    ) -> Result<(), String> {
        let id = batch.connection_id.clone();
        let result = self.ingest(batch, packet_no);
        if result.is_err() {
            self.rejected_batches = self.rejected_batches.saturating_add(1);
            if let Some(connection) = self.connections.get_mut(&id) {
                connection.limited = true;
            }
        }
        result
    }

    fn ingest(&mut self, batch: AuthenticatedHttp3Batch, packet_no: u64) -> Result<(), String> {
        if batch.alpn != "h3"
            || batch.connection_id.is_empty()
            || batch.connection_id.len() > 128
            || !batch
                .connection_id
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
            || batch.events.is_empty()
            || batch.events.len() > 256
        {
            return Err("Invalid authenticated HTTP/3 batch metadata or event count".into());
        }
        for event in &batch.events {
            validate_event(event)?;
        }
        if !self.connections.contains_key(&batch.connection_id)
            && self.connections.len() >= MAX_CONNECTIONS
        {
            return Err("HTTP/3 connection retention limit reached".into());
        }
        let connection = self.connections.entry(batch.connection_id).or_default();
        for event in batch.events {
            if !connection.streams.contains_key(&event.stream_id)
                && connection.streams.len() >= MAX_STREAMS
            {
                connection.limited = true;
                return Err("HTTP/3 request stream retention limit reached".into());
            }
            let cost = event_cost(&event);
            if self.retained_events >= MAX_EVENTS
                || self.retained_bytes.saturating_add(cost) > MAX_RETAINED_BYTES
            {
                connection.limited = true;
                return Err("HTTP/3 event or byte retention limit reached".into());
            }
            let halves = connection.streams.entry(event.stream_id).or_default();
            let half = halves.entry(event.sender).or_default();
            if half.ingest(event.event, packet_no)? {
                self.retained_events += 1;
                self.retained_bytes += cost;
            }
        }
        Ok(())
    }

    pub fn conversation(&self, id: &str) -> Option<Http3Conversation> {
        self.connections
            .get(id)
            .map(|connection| reconstruct::conversation(id, connection))
    }

    pub fn connection_ids(&self) -> impl Iterator<Item = &str> {
        self.connections.keys().map(String::as_str)
    }

    pub fn connection_for_packet(&self, packet_no: u64) -> Option<&str> {
        self.connections
            .iter()
            .find(|(_, connection)| {
                connection
                    .streams
                    .values()
                    .any(|halves| halves.values().any(|half| half.contains_packet(packet_no)))
            })
            .map(|(id, _)| id.as_str())
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

fn event_cost(event: &Http3Event) -> usize {
    512 + match &event.event {
        Http3EventKind::Headers { headers, .. } => headers
            .iter()
            .map(|header| header.name.len() + header.value.len() + 32)
            .sum(),
        Http3EventKind::Data { data, .. } => data.len(),
        _ => 0,
    }
}

fn validate_event(event: &Http3Event) -> Result<(), String> {
    if event.stream_id > MAX_OFFSET || event.stream_id % 4 != 0 {
        return Err("HTTP/3 input supports client-initiated request streams only".into());
    }
    let range = match &event.event {
        Http3EventKind::Headers {
            offset,
            wire_length,
            headers,
        } => {
            if headers.len() > MAX_HEADERS
                || headers
                    .iter()
                    .map(|header| {
                        header
                            .name
                            .len()
                            .saturating_add(header.value.len())
                            .saturating_add(32)
                    })
                    .sum::<usize>()
                    > MAX_HEADER_BYTES
            {
                return Err("HTTP/3 decoded header limit exceeded".into());
            }
            Some((*offset, *wire_length))
        }
        Http3EventKind::Data {
            offset,
            wire_length,
            data,
        } => {
            if data.len() > 512 * 1024
                || !wire_length
                    .checked_sub(data.len() as u64)
                    .is_some_and(|header| matches!(header, 2..=6 | 8..=10 | 12 | 16))
            {
                return Err("HTTP/3 DATA size or framing metadata is invalid".into());
            }
            Some((*offset, *wire_length))
        }
        Http3EventKind::Extension {
            offset,
            wire_length,
            frame_type,
        } => {
            if *frame_type > MAX_OFFSET
                || matches!(frame_type, 0 | 1 | 2 | 3 | 4 | 6 | 7 | 8 | 9 | 13)
                || (*frame_type == 5 && event.sender == Http3Sender::Client)
            {
                return Err(
                    "HTTP/3 known or control frame cannot masquerade as an extension".into(),
                );
            }
            Some((*offset, *wire_length))
        }
        Http3EventKind::Finished { final_size } | Http3EventKind::Reset { final_size, .. } => {
            if *final_size > MAX_OFFSET {
                return Err("Invalid QUIC stream final size".into());
            }
            if let Http3EventKind::Reset { error_code, .. } = &event.event {
                if *error_code > MAX_OFFSET {
                    return Err("Invalid QUIC reset code".into());
                }
            }
            None
        }
    };
    if let Some((offset, length)) = range {
        if !(2..=1_048_576).contains(&length)
            || offset
                .checked_add(length)
                .is_none_or(|end| end > MAX_OFFSET)
        {
            return Err("Invalid HTTP/3 plaintext frame range".into());
        }
    }
    Ok(())
}
