use crate::net::packet::Packet;

use super::{DnsMessage, DnsScope, DnsTransactionTracker, DnsTransport, dns_payload, parse_message, record_wire};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsReplyEvidence {
    pub packet: u64,
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
            resolver: packet.src.clone(),
            question: message.question.name.clone(),
            base_rcode: message.bytes[3] & 0x0f,
            response_code: record_wire::summarize_response(message, false).map(|summary| summary.rcode),
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
        let (transport, source_port, destination_port, payload) = dns_payload(packet)?;
        let message = parse_message(payload)?;
        let (client, client_port, resolver) = match message.response {
            true if source_port == 53 => (&packet.dst, destination_port, &packet.src),
            false if destination_port == 53 => (&packet.src, source_port, &packet.dst),
            _ => return None,
        };
        let key = DnsScope::from_packet(packet, transport).transaction(client, client_port, message.id, resolver);
        let exchange = self.exchanges.get(&key)?.entries.iter().find(|entry| {
            if message.response {
                entry.reply.as_ref().is_some_and(|reply| {
                    reply.first.packet == packet.no
                        || reply.alternates.iter().any(|other| other.evidence.packet == packet.no)
                })
            } else {
                entry.query.packet_no == packet.no || entry.repeat_frames.contains(&packet.no)
            }
        })?;
        let mut replies = Vec::new();
        let mut additional_replies_omitted = false;
        if let Some(reply) = &exchange.reply {
            replies.push(reply.first.clone());
            replies.extend(reply.alternates.iter().map(|alternate| alternate.evidence.clone()));
            additional_replies_omitted = reply.alternates_omitted;
        }
        Some(DnsExchangeEvidence {
            transaction_id: message.id,
            transport: match transport { DnsTransport::Udp => "UDP", DnsTransport::Tcp => "TCP" },
            question: exchange.query.question.name.clone(),
            query_type: exchange.query.question.qtype,
            query_class: exchange.query.question.qclass,
            query_packet: exchange.query.packet_no,
            repeated_query_packets: exchange.repeat_frames.clone(),
            additional_queries_omitted: exchange.repeats_omitted,
            client: client.clone(),
            client_port,
            expected_resolver: exchange.query.server.clone(),
            replies,
            additional_replies_omitted,
        })
    }
}
