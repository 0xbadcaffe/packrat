//! Reconstruction from explicitly authenticated helper events, never ciphertext.
use super::{MAX_HEADER_BYTES, MAX_HEADERS};
use std::collections::BTreeMap;

mod control;
mod model;
mod push;
mod reconstruct;
mod state;
mod validation;
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
    packet_connections: BTreeMap<u64, String>,
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
        let result = if let Some(prior) = self
            .packet_connections
            .get(&packet_no)
            .filter(|prior| *prior != &id)
        {
            if let Some(connection) = self.connections.get_mut(prior) {
                connection.limited = true;
                connection.revision += 1;
            }
            Err("HTTP/3 packet identity conflicts across authenticated connections".into())
        } else {
            self.ingest(batch, packet_no)
        };
        if let Some(connection) = self.connections.get_mut(&id) {
            connection.revision += 1;
        }
        if result.is_ok() {
            self.packet_connections.insert(packet_no, id.clone());
            while self.packet_connections.len() > 4096 {
                self.packet_connections.pop_first();
            }
        }
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
            validation::validate_event(event)?;
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
            if let Some(id) = event.event.push_id() {
                if connection.push_ids.len() >= 128 && !connection.push_ids.contains(&id) {
                    return Err("HTTP/3 retained push identifier limit reached".into());
                }
                connection.push_ids.insert(id);
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
        self.packet_connections.get(&packet_no).map(String::as_str)
    }

    pub fn connection_revision(&self, id: &str) -> Option<u64> {
        self.connections
            .get(id)
            .map(|connection| connection.revision)
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

fn event_cost(event: &Http3Event) -> usize {
    512 + match &event.event {
        Http3EventKind::Headers { headers, .. } | Http3EventKind::PushPromise { headers, .. } => {
            headers
                .iter()
                .map(|header| header.name.len() + header.value.len() + 32)
                .sum()
        }
        Http3EventKind::Data { data, .. } => data.len(),
        Http3EventKind::Settings { entries, .. } => entries.len() * 16,
        _ => 0,
    }
}
