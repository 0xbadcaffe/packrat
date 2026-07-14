//! Bounded DNS query/response integrity correlation.

use std::collections::HashMap;

use crate::net::packet::Packet;

const TRANSACTION_TTL_SECS: f64 = 30.0;
const RESPONSE_TTL_SECS: f64 = 5.0;
const MAX_TRANSACTIONS: usize = 2_048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsFinding {
    pub kind: DnsFindingKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsFindingKind {
    UnsolicitedResponse,
    QuestionMismatch,
    UnexpectedResponder,
    ConflictingResponse,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct TransactionKey {
    client: String,
    client_port: u16,
    id: u16,
}

#[derive(Debug, Clone)]
struct PendingQuery {
    server: String,
    question: Question,
    timestamp: f64,
}

#[derive(Debug, Clone)]
struct RecentResponse {
    server: String,
    question: Question,
    fingerprint: u64,
    timestamp: f64,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct Question {
    name: String,
    qtype: u16,
    qclass: u16,
}

struct DnsMessage<'a> {
    id: u16,
    response: bool,
    question: Question,
    bytes: &'a [u8],
}

#[derive(Debug, Default)]
pub struct DnsTransactionTracker {
    pending: HashMap<TransactionKey, PendingQuery>,
    recent: HashMap<TransactionKey, RecentResponse>,
}

impl DnsTransactionTracker {
    pub fn observe(&mut self, packet: &Packet) -> Vec<DnsFinding> {
        self.prune(packet.timestamp);
        let Some((source_port, destination_port, payload)) = udp_payload(packet) else {
            return Vec::new();
        };
        if source_port != 53 && destination_port != 53 {
            return Vec::new();
        }
        let Some(message) = parse_message(payload) else {
            return Vec::new();
        };

        if !message.response && destination_port == 53 {
            self.insert_query(
                TransactionKey {
                    client: packet.src.clone(),
                    client_port: source_port,
                    id: message.id,
                },
                PendingQuery {
                    server: packet.dst.clone(),
                    question: message.question,
                    timestamp: packet.timestamp,
                },
            );
            return Vec::new();
        }
        if !message.response || source_port != 53 {
            return Vec::new();
        }

        let key = TransactionKey {
            client: packet.dst.clone(),
            client_port: destination_port,
            id: message.id,
        };
        let fingerprint = stable_hash(message.bytes);
        if let Some(previous) = self.recent.get(&key) {
            if previous.server != packet.src || previous.fingerprint != fingerprint {
                return vec![DnsFinding {
                    kind: DnsFindingKind::ConflictingResponse,
                    detail: format!(
                        "transaction 0x{:04x} for {} received competing replies from {} and {}",
                        message.id, previous.question.name, previous.server, packet.src
                    ),
                }];
            }
            return Vec::new();
        }

        let Some(query) = self.pending.remove(&key) else {
            return vec![DnsFinding {
                kind: DnsFindingKind::UnsolicitedResponse,
                detail: format!(
                    "unsolicited transaction 0x{:04x} from {} to {}:{}",
                    message.id, packet.src, packet.dst, destination_port
                ),
            }];
        };

        let mut findings = Vec::new();
        if query.question != message.question {
            findings.push(DnsFinding {
                kind: DnsFindingKind::QuestionMismatch,
                detail: format!(
                    "transaction 0x{:04x} question changed from {} to {}",
                    message.id, query.question.name, message.question.name
                ),
            });
        }
        if query.server != packet.src {
            findings.push(DnsFinding {
                kind: DnsFindingKind::UnexpectedResponder,
                detail: format!(
                    "transaction 0x{:04x} expected {} but reply came from {}",
                    message.id, query.server, packet.src
                ),
            });
        }
        self.insert_response(
            key,
            RecentResponse {
                server: packet.src.clone(),
                question: message.question,
                fingerprint,
                timestamp: packet.timestamp,
            },
        );
        findings
    }

    pub fn clear(&mut self) {
        self.pending.clear();
        self.recent.clear();
    }

    fn insert_query(&mut self, key: TransactionKey, query: PendingQuery) {
        if self.pending.len() >= MAX_TRANSACTIONS && !self.pending.contains_key(&key) {
            if let Some(oldest) = self
                .pending
                .iter()
                .min_by(|left, right| left.1.timestamp.total_cmp(&right.1.timestamp))
                .map(|(key, _)| key.clone())
            {
                self.pending.remove(&oldest);
            }
        }
        self.pending.insert(key, query);
    }

    fn insert_response(&mut self, key: TransactionKey, response: RecentResponse) {
        if self.recent.len() >= MAX_TRANSACTIONS && !self.recent.contains_key(&key) {
            if let Some(oldest) = self
                .recent
                .iter()
                .min_by(|left, right| left.1.timestamp.total_cmp(&right.1.timestamp))
                .map(|(key, _)| key.clone())
            {
                self.recent.remove(&oldest);
            }
        }
        self.recent.insert(key, response);
    }

    fn prune(&mut self, now: f64) {
        self.pending.retain(|_, query| {
            now < query.timestamp || now - query.timestamp <= TRANSACTION_TTL_SECS
        });
        self.recent.retain(|_, response| {
            now < response.timestamp || now - response.timestamp <= RESPONSE_TTL_SECS
        });
    }
}

fn parse_message(bytes: &[u8]) -> Option<DnsMessage<'_>> {
    if bytes.len() < 12 || u16::from_be_bytes([bytes[4], bytes[5]]) == 0 {
        return None;
    }
    let (name, end) = parse_name(bytes, 12)?;
    let qtype = u16::from_be_bytes([*bytes.get(end)?, *bytes.get(end + 1)?]);
    let qclass = u16::from_be_bytes([*bytes.get(end + 2)?, *bytes.get(end + 3)?]);
    Some(DnsMessage {
        id: u16::from_be_bytes([bytes[0], bytes[1]]),
        response: bytes[2] & 0x80 != 0,
        question: Question {
            name,
            qtype,
            qclass,
        },
        bytes,
    })
}

fn parse_name(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut end = None;
    for _ in 0..128 {
        let length = *bytes.get(cursor)?;
        if length == 0 {
            return Some((
                labels.join(".").to_ascii_lowercase(),
                end.unwrap_or(cursor + 1),
            ));
        }
        if length & 0xc0 == 0xc0 {
            let second = *bytes.get(cursor + 1)?;
            let pointer = (((length & 0x3f) as usize) << 8) | second as usize;
            if pointer >= bytes.len() {
                return None;
            }
            end.get_or_insert(cursor + 2);
            cursor = pointer;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return None;
        }
        let label_start = cursor + 1;
        let label_end = label_start.checked_add(length as usize)?;
        let label = std::str::from_utf8(bytes.get(label_start..label_end)?).ok()?;
        labels.push(label.to_string());
        cursor = label_end;
        if labels.iter().map(String::len).sum::<usize>() + labels.len().saturating_sub(1) > 253 {
            return None;
        }
    }
    None
}

fn udp_payload(packet: &Packet) -> Option<(u16, u16, &[u8])> {
    let raw = packet.bytes.as_slice();
    let mut network = 14usize;
    let mut ether_type = u16::from_be_bytes([*raw.get(12)?, *raw.get(13)?]);
    while matches!(ether_type, 0x8100 | 0x88a8) {
        ether_type = u16::from_be_bytes([*raw.get(network + 2)?, *raw.get(network + 3)?]);
        network += 4;
    }
    let transport = match ether_type {
        0x0800 if raw.get(network + 9) == Some(&17) => {
            network + ((raw.get(network)? & 0x0f) as usize) * 4
        }
        0x86dd => ipv6_udp_offset(raw, network)?,
        _ => return None,
    };
    let source_port = u16::from_be_bytes([*raw.get(transport)?, *raw.get(transport + 1)?]);
    let destination_port = u16::from_be_bytes([*raw.get(transport + 2)?, *raw.get(transport + 3)?]);
    let udp_length =
        u16::from_be_bytes([*raw.get(transport + 4)?, *raw.get(transport + 5)?]) as usize;
    if udp_length < 8 {
        return None;
    }
    let payload_start = transport.checked_add(8)?;
    let payload_end = transport.checked_add(udp_length)?.min(raw.len());
    Some((
        source_port,
        destination_port,
        raw.get(payload_start..payload_end)?,
    ))
}

fn ipv6_udp_offset(raw: &[u8], network: usize) -> Option<usize> {
    let mut next = *raw.get(network + 6)?;
    let mut cursor = network + 40;
    for _ in 0..16 {
        if next == 17 {
            return Some(cursor);
        }
        match next {
            0 | 43 | 60 => {
                next = *raw.get(cursor)?;
                cursor = cursor.checked_add(((*raw.get(cursor + 1)? as usize) + 1) * 8)?;
            }
            51 => {
                next = *raw.get(cursor)?;
                cursor = cursor.checked_add(((*raw.get(cursor + 1)? as usize) + 2) * 4)?;
            }
            _ => return None,
        }
    }
    None
}

fn stable_hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}
