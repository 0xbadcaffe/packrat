use std::collections::{BTreeMap, HashMap};

use crate::net::packet::Packet;

use super::{DnsFinding, DnsFindingKind, DnsMessage, DnsScope, PendingQuery, record_wire};

const WINDOW_SECS: f64 = 30.0;
const THRESHOLD: usize = 20;
const MAX_NAMES: usize = 64;
const MAX_CLIENTS: usize = 512;

#[derive(Debug, Default)]
pub(super) struct NegativeAnswers {
    clients: HashMap<(DnsScope, String, String), NameWindow>,
}

#[derive(Debug)]
struct NameWindow {
    latest_time: f64,
    alerted: bool,
    names: BTreeMap<String, (f64, [u64; 2])>,
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
        if !is_nxdomain(message) || query.question.name.is_empty()
            || query.server != pkt.src || query.question != message.question
        {
            return None;
        }
        let now = pkt.timestamp;
        let key = (scope, pkt.dst.clone(), pkt.src.clone());
        if self.clients.len() >= MAX_CLIENTS && !self.clients.contains_key(&key) {
            self.clients.retain(|_, state| now - state.latest_time <= WINDOW_SECS);
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
        state.names.retain(|_, (time, _)| state.latest_time - *time <= WINDOW_SECS);
        if state.names.is_empty() {
            state.alerted = false;
        }
        let sample = (now, [query.packet_no, pkt.no]);
        if let Some(current) = state.names.get_mut(&query.question.name) {
            if now > current.0 {
                *current = sample;
            }
        } else {
            if state.names.len() >= MAX_NAMES {
                let oldest = state.names.iter().min_by(|a, b| a.1.0.total_cmp(&b.1.0))?.0.clone();
                state.names.remove(&oldest);
            }
            state.names.insert(query.question.name.clone(), sample);
        }
        let count = state.names.len();
        if count < THRESHOLD || state.alerted {
            return None;
        }
        state.alerted = true;
        Some(DnsFinding {
            kind: DnsFindingKind::NxDomainBurst,
            detail: format!(
                "{} received NXDOMAIN from {} for {count} distinct queried names in 30 seconds",
                pkt.dst, pkt.src
            ),
            related_packets: state.names.values().flat_map(|&(_, frames)| frames)
                .filter(|&frame| frame != pkt.no).collect(),
        })
    }
}

fn is_nxdomain(message: &DnsMessage<'_>) -> bool {
    message.bytes[3] & 0x0f == 3
        && record_wire::summarize_response(message, false).is_some_and(|summary| summary.rcode == 3)
}
