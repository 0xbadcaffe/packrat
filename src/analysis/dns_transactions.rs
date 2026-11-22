//! Bounded DNS query/response integrity correlation.

use std::collections::HashMap;

use crate::net::packet::Packet;
use sha2::{Digest, Sha256};

mod answers;
mod correlation;
mod external_resolver;
mod investigation;
mod negative_answers;
mod record_wire;

use correlation::{ExchangeBucket, ReplyMatch};
pub use investigation::{DnsExchangeEvidence, DnsReplyEvidence};

const TRANSACTION_TTL_SECS: f64 = 30.0;
const RESPONSE_TTL_SECS: f64 = 5.0;
const MAX_TRANSACTIONS: usize = 2_048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsFinding {
    pub kind: DnsFindingKind,
    pub detail: String,
    pub related_packets: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsFindingKind {
    ReplyWithoutObservedQuery,
    AmbiguousReply,
    NxDomainBurst,
    LargeTxtResponse,
    ExternalResolver,
    JndiLabelQuery,
    QuestionMismatch,
    UnexpectedResponder,
    ConflictingResponse,
    ChangedReply,
    ChangedAnswerSet,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct TransactionKey {
    scope: DnsScope,
    client: String,
    client_port: u16,
    id: u16,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct DnsScope {
    interface: Option<(u32, u32)>,
    outer_vlan: Option<u16>,
    inner_vlan: Option<u16>,
}

impl DnsScope {
    fn from_packet(packet: &Packet) -> Self {
        Self {
            interface: packet.capture.as_ref().map(|capture| {
                (capture.section_id, capture.interface_id)
            }),
            outer_vlan: packet.outer_vlan_id,
            inner_vlan: packet.vlan_id,
        }
    }
}

pub(crate) fn alert_correlation_key(packet: &Packet, finding: &DnsFinding) -> String {
    if matches!(
        finding.kind,
        DnsFindingKind::QuestionMismatch
            | DnsFindingKind::UnexpectedResponder
            | DnsFindingKind::ConflictingResponse
            | DnsFindingKind::ChangedReply
            | DnsFindingKind::ChangedAnswerSet
    ) && let Some(query) = finding.related_packets.first()
    {
        return format!("{:?}:query:{query}", DnsScope::from_packet(packet));
    }
    format!("{:?}:{}>{}", DnsScope::from_packet(packet), packet.src, packet.dst)
}

#[derive(Debug, Clone)]
struct PendingQuery {
    packet_no: u64,
    server: String,
    question: Question,
    timestamp: f64,
}

#[derive(Debug, Clone)]
struct RecentResponse {
    first: DnsReplyEvidence,
    question: Question,
    fingerprint: [u8; 32],
    answer_fingerprint: Option<[u8; 32]>,
    timestamp: f64,
    alternates: Vec<AlternateResponse>,
    alternates_omitted: bool,
}

#[derive(Debug, Clone)]
struct AlternateResponse {
    evidence: DnsReplyEvidence,
    fingerprint: [u8; 32],
}

impl RecentResponse {
    fn record_alternate(
        &mut self,
        packet: &Packet,
        message: &DnsMessage<'_>,
        fingerprint: [u8; 32],
    ) -> bool {
        if self.alternates.iter().any(|reply| {
            reply.fingerprint == fingerprint && reply.evidence.resolver == packet.src
        }) {
            return false;
        }
        if self.first.packet == packet.no || self.alternates.iter().any(|reply| reply.evidence.packet == packet.no) {
            return true;
        }
        if self.alternates.len() == 8 {
            self.alternates_omitted = true;
            return true;
        }
        self.alternates.push(AlternateResponse {
            evidence: DnsReplyEvidence::from_reply(packet, message),
            fingerprint,
        });
        true
    }
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
    answer_offset: usize,
    bytes: &'a [u8],
}

#[derive(Debug, Default)]
pub struct DnsTransactionTracker {
    exchanges: HashMap<TransactionKey, ExchangeBucket>,
    negative_answers: negative_answers::NegativeAnswers,
    external_resolvers: external_resolver::ExternalResolvers,
}

impl DnsTransactionTracker {
    pub fn observe(&mut self, packet: &Packet) -> Vec<DnsFinding> {
        let Some((source_port, destination_port, payload)) = udp_payload(packet) else {
            return Vec::new();
        };
        if source_port != 53 && destination_port != 53 {
            return Vec::new();
        }
        let Some(message) = parse_message(payload) else {
            return Vec::new();
        };
        let scope = DnsScope::from_packet(packet);

        if !message.response && destination_port == 53 {
            let jndi_label = message.bytes[2] & 0x78 == 0
                && message.bytes[4..6] == [0, 1]
                && message.question.qclass == 1
                && dns_name_has_label(&message.question.name, "jndi");
            self.insert_query(
                TransactionKey {
                    scope,
                    client: packet.src.clone(),
                    client_port: source_port,
                    id: message.id,
                },
                PendingQuery {
                    packet_no: packet.no,
                    server: packet.dst.clone(),
                    question: message.question,
                    timestamp: packet.timestamp,
                },
            );
            return if jndi_label {
                vec![DnsFinding {
                    kind: DnsFindingKind::JndiLabelQuery,
                    related_packets: Vec::new(),
                    detail: format!("{} sent a DNS question with a standalone JNDI label to {}; lookup origin and exploitation are unverified", packet.src, packet.dst),
                }]
            } else {
                Vec::new()
            };
        }
        if !message.response || source_port != 53 {
            return Vec::new();
        }

        let key = TransactionKey {
            scope,
            client: packet.dst.clone(),
            client_port: destination_port,
            id: message.id,
        };
        let (exchange, ambiguous) = if let Some(bucket) = self.exchanges.get_mut(&key) {
            bucket.expire(packet.timestamp);
            match bucket.find_reply(packet.timestamp, &packet.src, &message.question) {
                ReplyMatch::Matched(index) => (Some(&mut bucket.entries[index]), false),
                ReplyMatch::Missing => (None, false),
                ReplyMatch::Ambiguous => (None, true),
            }
        } else {
            (None, false)
        };
        let Some(exchange) = exchange else {
            let reason = if ambiguous {
                "could not uniquely correlate a retained query"
            } else {
                "no matching query retained"
            };
            return vec![DnsFinding {
                kind: if ambiguous { DnsFindingKind::AmbiguousReply } else { DnsFindingKind::ReplyWithoutObservedQuery },
                related_packets: Vec::new(),
                detail: format!(
                    "{reason} for transaction 0x{:04x} from {} to {}:{}",
                    message.id, packet.src, packet.dst, destination_port
                ),
            }];
        };
        let query = &exchange.query;
        let fingerprint = Sha256::digest(message.bytes).into();
        if let Some(previous) = &mut exchange.reply {
            if previous.first.resolver != packet.src {
                if !previous.record_alternate(packet, &message, fingerprint) {
                    return Vec::new();
                }
                return vec![DnsFinding {
                    kind: DnsFindingKind::ConflictingResponse,
                    related_packets: vec![query.packet_no, previous.first.packet],
                    detail: format!(
                        "transaction 0x{:04x} for {} received competing replies from {} and {}",
                        message.id, previous.question.name, previous.first.resolver, packet.src
                    ),
                }];
            }
            if previous.fingerprint != fingerprint {
                let (kind, difference) = if previous.question != message.question {
                    (DnsFindingKind::QuestionMismatch, "a different question in the reply")
                } else {
                    match (
                        previous.answer_fingerprint,
                        answers::answer_fingerprint(message.bytes, message.answer_offset),
                    ) {
                        (Some(before), Some(after)) if before == after => return Vec::new(),
                        (Some(_), Some(_)) => (
                            DnsFindingKind::ChangedAnswerSet,
                            "a different answer set or base response code",
                        ),
                        _ => (
                            DnsFindingKind::ChangedReply,
                            "different reply bytes; answer comparison unavailable",
                        ),
                    }
                };
                if !previous.record_alternate(packet, &message, fingerprint) {
                    return Vec::new();
                }
                return vec![DnsFinding {
                    kind,
                    related_packets: vec![query.packet_no, previous.first.packet],
                    detail: format!(
                        "transaction 0x{:04x} for {} received {difference} from resolver {}",
                        message.id, previous.question.name, previous.first.resolver,
                    ),
                }];
            }
            return Vec::new();
        }

        let mut findings = Vec::new();
        if query.question != message.question {
            findings.push(DnsFinding {
                kind: DnsFindingKind::QuestionMismatch,
                related_packets: vec![query.packet_no],
                detail: format!(
                    "transaction 0x{:04x} question changed from {} to {}",
                    message.id, query.question.name, message.question.name
                ),
            });
        }
        if query.server != packet.src {
            findings.push(DnsFinding {
                kind: DnsFindingKind::UnexpectedResponder,
                related_packets: vec![query.packet_no],
                detail: format!(
                    "transaction 0x{:04x} expected {} but reply came from {}",
                    message.id, query.server, packet.src
                ),
            });
        }
        findings.extend(self.negative_answers.observe(scope, packet, query, &message));
        findings.extend(self.external_resolvers.observe(scope, packet, query, &message));
        if query.server == packet.src && query.question == message.question
            && message.question.qtype == 16 && message.question.qclass == 1
            && let Some(summary) = record_wire::summarize_response(&message, true)
            && summary.rcode == 0 && summary.answer_txt_bytes > 512
        {
            findings.push(DnsFinding {
                kind: DnsFindingKind::LargeTxtResponse,
                detail: format!(
                    "{} returned {} bytes of TXT answer data for {}",
                    packet.src, summary.answer_txt_bytes, message.question.name,
                ),
                related_packets: vec![query.packet_no],
            });
        }
        exchange.reply = Some(RecentResponse {
            first: DnsReplyEvidence::from_reply(packet, &message),
            question: message.question,
            fingerprint,
            answer_fingerprint: answers::answer_fingerprint(message.bytes, message.answer_offset),
            timestamp: packet.timestamp,
            alternates: Vec::new(),
            alternates_omitted: false,
        });
        findings
    }

    pub fn clear(&mut self) {
        self.exchanges.clear();
        self.negative_answers.clear();
        self.external_resolvers.clear();
    }

    fn insert_query(&mut self, key: TransactionKey, query: PendingQuery) {
        if self.exchanges.len() >= MAX_TRANSACTIONS && !self.exchanges.contains_key(&key) {
            self.exchanges.retain(|_, bucket| {
                bucket.expire(query.timestamp);
                !bucket.is_empty()
            });
            if self.exchanges.len() >= MAX_TRANSACTIONS {
                return;
            }
        }
        self.exchanges.entry(key).or_default().record(query);
    }
}

fn dns_name_has_label(name: &str, label: &str) -> bool {
    // parse_name escapes literal dots and backslashes inside a wire label.
    let mut escaped = false;
    name.split(|ch| {
        let separator = ch == '.' && !escaped;
        escaped = ch == '\\' && !escaped;
        separator
    }).any(|part| part == label)
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
        answer_offset: end + 4,
        bytes,
    })
}

pub(crate) fn parse_name(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut end = None;
    let mut wire_name_length = 1;
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
            if pointer >= cursor {
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
        wire_name_length += usize::from(length) + 1;
        if wire_name_length > 255 {
            return None;
        }
        let mut escaped = String::with_capacity(label.len());
        for char in label.chars() {
            match char {
                '.' | '\\' => {
                    escaped.push('\\');
                    escaped.push(char);
                }
                char if char.is_control() => escaped.extend(char.escape_default()),
                char => escaped.push(char),
            }
        }
        labels.push(escaped);
        cursor = label_end;
    }
    None
}

pub(crate) fn udp_payload(packet: &Packet) -> Option<(u16, u16, &[u8])> {
    let raw = packet.bytes.as_slice();
    let mut network = 14usize;
    let mut ether_type = u16::from_be_bytes([*raw.get(12)?, *raw.get(13)?]);
    while matches!(ether_type, 0x8100 | 0x88a8) {
        ether_type = u16::from_be_bytes([*raw.get(network + 2)?, *raw.get(network + 3)?]);
        network += 4;
    }
    let (transport, network_end) = match ether_type {
        0x0800 if raw.get(network + 9) == Some(&17) => {
            let ihl = usize::from(raw.get(network)? & 0x0f) * 4;
            let fragment = u16::from_be_bytes(raw.get(network + 6..network + 8)?.try_into().ok()?);
            if ihl < 20 || fragment & 0x3fff != 0 {
                return None;
            }
            let length = u16::from_be_bytes(raw.get(network + 2..network + 4)?.try_into().ok()?);
            (network + ihl, network + usize::from(length))
        }
        0x86dd => {
            let length = u16::from_be_bytes(raw.get(network + 4..network + 6)?.try_into().ok()?);
            (ipv6_udp_offset(raw, network)?, network + 40 + usize::from(length))
        }
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
    let payload_end = transport.checked_add(udp_length)?;
    if payload_end > network_end {
        return None;
    }
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
