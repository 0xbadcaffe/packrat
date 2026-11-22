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
    pub additional_queries_omitted: bool,
    pub client: String,
    pub client_port: u16,
    pub expected_resolver: String,
    pub replies: Vec<DnsReplyEvidence>,
    pub additional_replies_omitted: bool,
}

impl DnsTransactionTracker {
    /// Use both scope and frame identity; the wire transaction ID can be reused.
    pub fn exchange_for_packet(&self, packet: &Packet) -> Option<DnsExchangeEvidence> {
        self.exchange_from_wire(packet)
            .or_else(|| self.exchange_from_tcp_frame(packet))
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
                entry.query.packet_no == packet.no || entry.repeat_frames.contains(&packet.no)
            }
        })?;
        Some(exchange_evidence(&key, exchange))
    }

    fn exchange_from_tcp_frame(&self, packet: &Packet) -> Option<DnsExchangeEvidence> {
        if packet.src_port != Some(53) && packet.dst_port != Some(53) {
            return None;
        }
        let (source, destination) = crate::analysis::stream::tcp_port_pair(packet)?;
        let (client, client_port, resolver, response) = match (source, destination) {
            (53, port) if port != 53 => (&packet.dst, port, &packet.src, true),
            (port, 53) if port != 53 => (&packet.src, port, &packet.dst, false),
            _ => return None,
        };
        let scope = DnsScope::from_packet(packet, DnsTransport::Tcp);
        let mut matching = self
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
                    entry.query.packet_no == packet.no || entry.query.frames.contains(&packet.no)
                }
            });
        let (key, entry) = matching.next()?;
        // A frame shared by multiple messages is not a unique transaction selector.
        matching
            .next()
            .is_none()
            .then(|| exchange_evidence(key, entry))
    }
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
        additional_queries_omitted: exchange.repeats_omitted,
        client: key.client.clone(),
        client_port: key.client_port,
        expected_resolver: exchange.query.server.clone(),
        replies,
        additional_replies_omitted,
    }
}
