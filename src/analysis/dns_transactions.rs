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
mod replies;
mod tcp_wire;

use correlation::{ExchangeBucket, ReplyMatch};
pub use investigation::{DnsExchangeEvidence, DnsReplyEvidence};
use replies::{RecentResponse, ReplyOutcome, question_mismatch};

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
    InvalidQuestionCount,
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
    tcp_resolver: Option<String>,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
enum DnsTransport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct DnsScope {
    interface: Option<(u32, u32)>,
    outer_vlan: Option<u16>,
    inner_vlan: Option<u16>,
    transport: DnsTransport,
}

impl DnsScope {
    fn from_packet(packet: &Packet, transport: DnsTransport) -> Self {
        Self {
            interface: packet.capture.as_ref().map(|capture| {
                (capture.section_id, capture.interface_id)
            }),
            outer_vlan: packet.outer_vlan_id,
            inner_vlan: packet.vlan_id,
            transport,
        }
    }

    fn transaction(self, client: &str, client_port: u16, id: u16, resolver: &str) -> TransactionKey {
        TransactionKey {
            scope: self,
            client: client.into(),
            client_port,
            id,
            tcp_resolver: (self.transport == DnsTransport::Tcp).then(|| resolver.into()),
        }
    }
}

fn dns_payload(packet: &Packet) -> Option<(DnsTransport, u16, u16, &[u8])> {
    if let Some((source, destination, payload)) = udp_payload(packet) {
        return Some((DnsTransport::Udp, source, destination, payload));
    }
    let (source, destination, payload) = tcp_wire::dns_payload(packet)?;
    Some((DnsTransport::Tcp, source, destination, payload))
}

pub(crate) fn alert_correlation_key(packet: &Packet, finding: &DnsFinding) -> String {
    let transport = dns_payload(packet).map_or(DnsTransport::Udp, |(transport, ..)| transport);
    let scope = DnsScope::from_packet(packet, transport);
    if matches!(
        finding.kind,
        DnsFindingKind::QuestionMismatch
            | DnsFindingKind::UnexpectedResponder
            | DnsFindingKind::ConflictingResponse
            | DnsFindingKind::ChangedReply
            | DnsFindingKind::ChangedAnswerSet
    ) && let Some(query) = finding.related_packets.first()
    {
        return format!("{scope:?}:query:{query}");
    }
    format!("{scope:?}:{}>{}", packet.src, packet.dst)
}

#[derive(Debug, Clone)]
struct PendingQuery {
    packet_no: u64,
    server: String,
    question: Question,
    timestamp: f64,
    wire_fingerprint: [u8; 32],
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

impl DnsMessage<'_> {
    fn truncated(&self) -> bool {
        self.bytes[2] & 0x02 != 0
    }
}

#[derive(Debug, Default)]
pub struct DnsTransactionTracker {
    exchanges: HashMap<TransactionKey, ExchangeBucket>,
    negative_answers: negative_answers::NegativeAnswers,
    external_resolvers: external_resolver::ExternalResolvers,
}

impl DnsTransactionTracker {
    pub fn observe(&mut self, packet: &Packet) -> Vec<DnsFinding> {
        let Some((transport, source_port, destination_port, payload)) = dns_payload(packet) else {
            return Vec::new();
        };
        if source_port != 53 && destination_port != 53 {
            return Vec::new();
        }
        let Some(header) = DnsQueryHeader::parse(payload) else {
            return Vec::new();
        };
        if (header.response && source_port != 53) || (!header.response && destination_port != 53) {
            return Vec::new();
        }
        if header.questions > 1 {
            return vec![DnsFinding {
                kind: DnsFindingKind::InvalidQuestionCount,
                related_packets: Vec::new(),
                detail: format!(
                    "DNS {} 0x{:04x} from {} to {} declares {} questions; standard queries and replies can carry at most one",
                    if header.response { "reply" } else { "query" },
                    header.id, packet.src, packet.dst, header.questions,
                ),
            }];
        }
        let Some(message) = parse_single_question(payload, header) else {
            return Vec::new();
        };
        let scope = DnsScope::from_packet(packet, transport);

        if !message.response {
            let jndi_label = message.question.qclass == 1
                && dns_name_has_label(&message.question.name, "jndi");
            self.insert_query(
                scope.transaction(&packet.src, source_port, message.id, &packet.dst),
                PendingQuery {
                    packet_no: packet.no,
                    server: packet.dst.clone(),
                    question: message.question,
                    timestamp: packet.timestamp,
                    wire_fingerprint: Sha256::digest(message.bytes).into(),
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
        let key = scope.transaction(&packet.dst, destination_port, message.id, &packet.src);
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
        if let Some(previous) = &mut exchange.reply {
            match previous.observe_follow_up(packet, query, &message) {
                ReplyOutcome::FirstMatch => {}
                ReplyOutcome::Repeat => return Vec::new(),
                ReplyOutcome::Finding(finding) => return vec![finding],
            }
        } else {
            let matches = query.question == message.question;
            exchange.reply = Some(RecentResponse::new(packet, &message, matches));
            if !matches {
                return vec![question_mismatch(query, &message)];
            }
        }

        let mut findings = Vec::new();
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
        if query.server == packet.src
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

struct DnsQueryHeader {
    id: u16,
    response: bool,
    questions: u16,
}

impl DnsQueryHeader {
    fn parse(bytes: &[u8]) -> Option<Self> {
        // The tracker decodes QUERY questions, not other opcode-specific sections.
        if bytes.len() < 12 || bytes[2] & 0x78 != 0 {
            return None;
        }
        Some(Self {
            id: u16::from_be_bytes([bytes[0], bytes[1]]),
            response: bytes[2] & 0x80 != 0,
            questions: u16::from_be_bytes([bytes[4], bytes[5]]),
        })
    }
}

fn parse_message(bytes: &[u8]) -> Option<DnsMessage<'_>> {
    parse_single_question(bytes, DnsQueryHeader::parse(bytes)?)
}

pub(crate) fn wire_query_name(packet: &Packet) -> Option<String> {
    let (_, 53, payload) = udp_payload(packet)? else { return None };
    let message = parse_message(payload)?;
    (!message.response && message.question.qclass == 1).then_some(message.question.name)
}

fn parse_single_question(bytes: &[u8], header: DnsQueryHeader) -> Option<DnsMessage<'_>> {
    if header.questions != 1 {
        return None;
    }
    let (name, end) = parse_name(bytes, 12)?;
    let qtype = u16::from_be_bytes([*bytes.get(end)?, *bytes.get(end + 1)?]);
    let qclass = u16::from_be_bytes([*bytes.get(end + 2)?, *bytes.get(end + 3)?]);
    Some(DnsMessage {
        id: header.id,
        response: header.response,
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
    if packet.capture.as_ref().is_some_and(|metadata| metadata.link_type != 1) {
        return None;
    }
    let raw = packet.bytes.as_slice();
    let mut network = 14usize;
    let mut ether_type = u16::from_be_bytes([*raw.get(12)?, *raw.get(13)?]);
    for _ in 0..2 {
        if !matches!(ether_type, 0x8100 | 0x88a8) {
            break;
        }
        ether_type = u16::from_be_bytes([*raw.get(network + 2)?, *raw.get(network + 3)?]);
        network += 4;
    }
    let (transport, network_end) = match ether_type {
        0x0800 if raw.get(network)? >> 4 == 4 && raw.get(network + 9) == Some(&17) => {
            let ihl = usize::from(raw.get(network)? & 0x0f) * 4;
            let fragment = u16::from_be_bytes(raw.get(network + 6..network + 8)?.try_into().ok()?);
            if ihl < 20 || fragment & 0x3fff != 0 {
                return None;
            }
            let length = u16::from_be_bytes(raw.get(network + 2..network + 4)?.try_into().ok()?);
            (network + ihl, network + usize::from(length))
        }
        0x86dd if raw.get(network)? >> 4 == 6 => {
            let length = u16::from_be_bytes(raw.get(network + 4..network + 6)?.try_into().ok()?);
            let end = network + 40 + usize::from(length);
            (ipv6_udp_offset(&raw[..end.min(raw.len())], network)?, end)
        }
        _ => return None,
    };
    let udp = raw.get(transport..network_end.min(raw.len()))?;
    let &[src_hi, src_lo, dst_hi, dst_lo, len_hi, len_lo, _, _] = udp.first_chunk::<8>()?;
    let udp_length = usize::from(u16::from_be_bytes([len_hi, len_lo]));
    Some((
        u16::from_be_bytes([src_hi, src_lo]),
        u16::from_be_bytes([dst_hi, dst_lo]),
        udp.get(8..udp_length)?,
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
