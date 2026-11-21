use std::collections::{BTreeMap, HashMap};

use crate::net::packet::Packet;

use super::{DnsFinding, DnsFindingKind, DnsMessage, DnsScope, PendingQuery, parse_name};

const WINDOW_SECS: f64 = 30.0;
const THRESHOLD: usize = 20;
const MAX_NAMES: usize = 64;
const MAX_CLIENTS: usize = 512;
const MAX_RECORDS: usize = 128;

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
    let bytes = message.bytes;
    message.response && bytes[2] & 0x7a == 0 && bytes[3] & 0x0f == 3
        && bytes[4..6] == [0, 1]
        && extended_rcode(bytes, message.answer_offset) == Some(0)
}

fn extended_rcode(bytes: &[u8], mut offset: usize) -> Option<u8> {
    let word = |at: usize| u16::from_be_bytes([bytes[at], bytes[at + 1]]) as usize;
    let additional_start = word(6) + word(8);
    let count = additional_start + word(10);
    if count > MAX_RECORDS || bytes.len() > 4096 {
        return None;
    }
    let mut extension = None;
    for record in 0..count {
        let (owner, fields) = parse_name(bytes, offset)?;
        let header = bytes.get(fields..fields + 10)?;
        let data_size = u16::from_be_bytes([header[8], header[9]]) as usize;
        offset = fields + 10 + data_size;
        if offset > bytes.len() {
            return None;
        }
        if header[..2] == [0, 41] {
            if record < additional_start || !owner.is_empty() || extension.is_some() {
                return None;
            }
            extension = Some(header[4]);
        }
    }
    (offset == bytes.len()).then_some(extension.unwrap_or(0))
}
