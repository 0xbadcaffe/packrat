use crate::net::packet::Packet;

use super::correlation::Exchange;
use super::{
    DnsMessage, DnsScope, DnsTransactionTracker, DnsTransport, TransactionKey, dns_payload,
    parse_message, record_wire,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsReplyEvidence {
    pub packet: u64,
    pub frames: Vec<u64>,
    pub resolver: String,
    pub question: String,
    pub base_rcode: u8,
    pub response_code: Option<u16>,
    pub truncated: bool,
}

impl DnsReplyEvidence {
    pub(super) fn from_reply(packet: &Packet, message: &DnsMessage<'_>) -> Self {
        Self {
            packet: packet.no,
            frames: message.frames.to_vec(),
            resolver: packet.src.clone(),
            question: message.question.name.clone(),
            base_rcode: message.bytes[3] & 0x0f,
            response_code: record_wire::summarize_response(message, false)
                .map(|summary| summary.rcode),
            truncated: message.truncated(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsExchangeEvidence {
    pub transaction_id: u16,
    pub transport: &'static str,
    pub question: String,
    pub query_type: u16,
    pub query_class: u16,
    pub query_packet: u64,
    pub query_frames: Vec<u64>,
    pub repeated_query_packets: Vec<u64>,
    pub timing_retry: Option<DnsQueryRetryEvidence>,
    pub additional_queries_omitted: bool,
    pub client: String,
    pub client_port: u16,
    pub expected_resolver: String,
    pub replies: Vec<DnsReplyEvidence>,
    pub additional_replies_omitted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQueryRetryEvidence {
    pub packet: u64,
    pub frames: Vec<u64>,
}

impl DnsExchangeEvidence {
    pub(crate) fn frame_numbers(&self) -> impl Iterator<Item = u64> + '_ {
        std::iter::once(self.query_packet)
            .chain(self.query_frames.iter().copied())
            .chain(self.repeated_query_packets.iter().copied())
            .chain(self.timing_retry.iter().flat_map(|retry| {
                std::iter::once(retry.packet).chain(retry.frames.iter().copied())
            }))
            .chain(self.replies.iter().flat_map(|reply| {
                std::iter::once(reply.packet).chain(reply.frames.iter().copied())
            }))
    }
}

impl DnsTransactionTracker {
    /// Use both scope and frame identity; the wire transaction ID can be reused.
    pub fn exchange_for_packet(&self, packet: &Packet) -> Option<DnsExchangeEvidence> {
        let mut exchanges = self.exchanges_for_packet(packet);
        (exchanges.len() == 1).then(|| exchanges.remove(0))
    }

    pub fn exchanges_for_packet(&self, packet: &Packet) -> Vec<DnsExchangeEvidence> {
        let tcp = self.exchanges_from_tcp_frame(packet);
        if tcp.is_empty() {
            self.exchange_from_wire(packet).into_iter().collect()
        } else {
            tcp
        }
    }

    fn exchange_from_wire(&self, packet: &Packet) -> Option<DnsExchangeEvidence> {
        let (transport, source_port, destination_port, payload) = dns_payload(packet)?;
        let message = parse_message(payload)?;
        let (client, client_port, resolver) = match message.response {
            true if source_port == 53 => (&packet.dst, destination_port, &packet.src),
            false if destination_port == 53 => (&packet.src, source_port, &packet.dst),
            _ => return None,
        };
        let key = DnsScope::from_packet(packet, transport).transaction(
            client,
            client_port,
            message.id,
            resolver,
        );
        let exchange = self.exchanges.get(&key)?.entries.iter().find(|entry| {
            if message.response {
                entry.reply.as_ref().is_some_and(|reply| {
                    reply.first.packet == packet.no
                        || reply
                            .alternates
                            .iter()
                            .any(|other| other.evidence.packet == packet.no)
                })
            } else {
                query_contains_frame(entry, packet.no)
            }
        })?;
        Some(exchange_evidence(&key, exchange))
    }

    fn exchanges_from_tcp_frame(&self, packet: &Packet) -> Vec<DnsExchangeEvidence> {
        if packet.src_port != Some(53) && packet.dst_port != Some(53) {
            return Vec::new();
        }
        let Some((source, destination)) = crate::analysis::stream::tcp_port_pair(packet) else {
            return Vec::new();
        };
        if (packet.src_port, packet.dst_port) != (Some(source), Some(destination)) {
            return Vec::new();
        }
        let (client, client_port, resolver, response) = match (source, destination) {
            (53, port) if port != 53 => (&packet.dst, port, &packet.src, true),
            (port, 53) if port != 53 => (&packet.src, port, &packet.dst, false),
            _ => return Vec::new(),
        };
        let scope = DnsScope::from_packet(packet, DnsTransport::Tcp);
        let mut matching: Vec<_> = self
            .exchanges
            .iter()
            .filter(|(key, _)| {
                key.scope == scope
                    && key.client == *client
                    && key.client_port == client_port
                    && key.tcp_resolver.as_ref() == Some(resolver)
            })
            .flat_map(|(key, bucket)| bucket.entries.iter().map(move |entry| (key, entry)))
            .filter(|(_, entry)| {
                if response {
                    entry.reply.as_ref().is_some_and(|reply| {
                        let contains = |evidence: &DnsReplyEvidence| {
                            evidence.packet == packet.no || evidence.frames.contains(&packet.no)
                        };
                        contains(&reply.first)
                            || reply
                                .alternates
                                .iter()
                                .any(|other| contains(&other.evidence))
                    })
                } else {
                    query_contains_frame(entry, packet.no)
                }
            })
            .collect();
        matching.sort_unstable_by_key(|(key, entry)| {
            let question = &entry.query.question;
            (
                key.id,
                entry.query.packet_no,
                &question.name,
                question.qtype,
                question.qclass,
            )
        });
        matching
            .into_iter()
            .take(128)
            .map(|(key, entry)| exchange_evidence(key, entry))
            .collect()
    }
}

fn query_contains_frame(exchange: &Exchange, frame: u64) -> bool {
    exchange.query.packet_no == frame
        || exchange.query.frames.contains(&frame)
        || exchange.repeat_frames.contains(&frame)
        || exchange.timing_retry().is_some_and(|(retry, frames)| retry == frame || frames.contains(&frame))
}

fn exchange_evidence(key: &TransactionKey, exchange: &Exchange) -> DnsExchangeEvidence {
    let mut replies = Vec::new();
    let mut additional_replies_omitted = false;
    if let Some(reply) = &exchange.reply {
        replies.push(reply.first.clone());
        replies.extend(
            reply
                .alternates
                .iter()
                .map(|alternate| alternate.evidence.clone()),
        );
        additional_replies_omitted = reply.alternates_omitted;
    }
    DnsExchangeEvidence {
        transaction_id: key.id,
        transport: match key.scope.transport {
            DnsTransport::Udp => "UDP",
            DnsTransport::Tcp => "TCP",
        },
        question: exchange.query.question.name.clone(),
        query_type: exchange.query.question.qtype,
        query_class: exchange.query.question.qclass,
        query_packet: exchange.query.packet_no,
        query_frames: exchange.query.frames.clone(),
        repeated_query_packets: exchange.repeat_frames.clone(),
        timing_retry: exchange.timing_retry().map(|(packet, frames)| DnsQueryRetryEvidence {
            packet,
            frames: frames.to_vec(),
        }),
        additional_queries_omitted: exchange.repeats_omitted,
        client: key.client.clone(),
        client_port: key.client_port,
        expected_resolver: exchange.query.server.clone(),
        replies,
        additional_replies_omitted,
    }
}
