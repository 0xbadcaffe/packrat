use std::collections::{BTreeMap, HashMap};

use crate::net::packet::Packet;

use super::{DnsFinding, DnsFindingKind, DnsMessage, DnsScope, PendingQuery, record_wire};

const WINDOW_SECS: f64 = 30.0;
const THRESHOLD: usize = 20;
const MAX_NAMES: usize = 64;
const MAX_CLIENTS: usize = 512;
const FRAMES_PER_MESSAGE: usize = 3;
const _: () = assert!(
    THRESHOLD * 2 * FRAMES_PER_MESSAGE <= crate::analysis::alert_center::MAX_ALERT_PACKET_REFS
);

#[derive(Debug, Default)]
pub(super) struct NegativeAnswers {
    clients: HashMap<(DnsScope, String, String), NameWindow>,
}

#[derive(Debug)]
struct NameWindow {
    latest_time: f64,
    alerted: bool,
    names: BTreeMap<String, NameSample>,
}

#[derive(Debug)]
struct NameSample {
    timestamp: f64,
    frames: Vec<u64>,
    sampled: bool,
}

impl NameSample {
    fn new(packet: &Packet, query: &PendingQuery, message: &DnsMessage<'_>) -> Self {
        let mut sample = Self {
            timestamp: packet.timestamp,
            frames: Vec::new(),
            sampled: false,
        };
        sample.include_message(query.packet_no, &query.frames);
        sample.include_message(packet.no, message.frames);
        sample
    }

    fn include_message(&mut self, completion: u64, frames: &[u64]) {
        // Keep the completion frame even when the message needs more segments than fit.
        let mut segments = frames.iter().copied().filter(|&frame| frame != completion);
        self.frames
            .extend(segments.by_ref().take(FRAMES_PER_MESSAGE - 1));
        self.frames.push(completion);
        self.sampled |= segments.next().is_some();
    }
}

impl NegativeAnswers {
    pub(super) fn clear(&mut self) {
        self.clients.clear();
    }

    pub(super) fn observe(
        &mut self,
        scope: DnsScope,
        pkt: &Packet,
        query: &PendingQuery,
        message: &DnsMessage<'_>,
    ) -> Option<DnsFinding> {
        if !is_nxdomain(message)
            || query.question.name.is_empty()
            || query.server != pkt.src
            || query.question != message.question
        {
            return None;
        }
        let now = pkt.timestamp;
        let key = (scope, pkt.dst.clone(), pkt.src.clone());
        if self.clients.len() >= MAX_CLIENTS && !self.clients.contains_key(&key) {
            self.clients
                .retain(|_, state| now - state.latest_time <= WINDOW_SECS);
            if self.clients.len() >= MAX_CLIENTS {
                return None;
            }
        }
        let state = self.clients.entry(key).or_insert_with(|| NameWindow {
            latest_time: now,
            alerted: false,
            names: BTreeMap::new(),
        });
        if state.latest_time - now > WINDOW_SECS {
            return None;
        }
        state.latest_time = state.latest_time.max(now);
        state
            .names
            .retain(|_, sample| state.latest_time - sample.timestamp <= WINDOW_SECS);
        if state.names.is_empty() {
            state.alerted = false;
        }
        if let Some(current) = state.names.get_mut(&query.question.name) {
            if now > current.timestamp {
                *current = NameSample::new(pkt, query, message);
            }
        } else {
            if state.names.len() >= MAX_NAMES {
                let oldest = state
                    .names
                    .iter()
                    .min_by(|a, b| a.1.timestamp.total_cmp(&b.1.timestamp))?
                    .0
                    .clone();
                state.names.remove(&oldest);
            }
            state.names.insert(
                query.question.name.clone(),
                NameSample::new(pkt, query, message),
            );
        }
        let count = state.names.len();
        if count < THRESHOLD || state.alerted {
            return None;
        }
        state.alerted = true;
        let evidence_note = if state.names.values().any(|sample| sample.sampled) {
            "; contributing frame references sampled"
        } else {
            ""
        };
        let mut related_packets: Vec<_> = state
            .names
            .values()
            .flat_map(|sample| sample.frames.iter().copied())
            .filter(|&frame| frame != pkt.no)
            .collect();
        related_packets.sort_unstable();
        related_packets.dedup();
        Some(DnsFinding {
            kind: DnsFindingKind::NxDomainBurst,
            detail: format!(
                "{} received NXDOMAIN from {} for {count} distinct queried names in 30 seconds{evidence_note}",
                pkt.dst, pkt.src
            ),
            related_packets,
        })
    }
}

fn is_nxdomain(message: &DnsMessage<'_>) -> bool {
    message.bytes[3] & 0x0f == 3
        && record_wire::summarize_response(message, false).is_some_and(|summary| summary.rcode == 3)
}
