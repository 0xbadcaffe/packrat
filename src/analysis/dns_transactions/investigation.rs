use crate::net::packet::Packet;

use super::{DnsMessage, DnsScope, DnsTransactionTracker, TransactionKey, parse_message, udp_payload};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsReplyEvidence {
    pub packet: u64,
    pub resolver: String,
    pub question: String,
    pub base_rcode: u8,
}

impl DnsReplyEvidence {
    pub(super) fn from_reply(packet: &Packet, message: &DnsMessage<'_>) -> Self {
        Self {
            packet: packet.no,
            resolver: packet.src.clone(),
            question: message.question.name.clone(),
            base_rcode: message.bytes[3] & 0x0f,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsExchangeEvidence {
    pub transaction_id: u16,
    pub question: String,
    pub query_type: u16,
    pub query_class: u16,
    pub query_packet: u64,
    pub client: String,
    pub client_port: u16,
    pub expected_resolver: String,
    pub replies: Vec<DnsReplyEvidence>,
    pub additional_replies_omitted: bool,
}

impl DnsTransactionTracker {
    /// Use both scope and frame identity; the wire transaction ID can be reused.
    pub fn exchange_for_packet(&self, packet: &Packet) -> Option<DnsExchangeEvidence> {
        let (source_port, destination_port, payload) = udp_payload(packet)?;
        let message = parse_message(payload)?;
        let (client, client_port) = match message.response {
            true if source_port == 53 => (&packet.dst, destination_port),
            false if destination_port == 53 => (&packet.src, source_port),
            _ => return None,
        };
        let key = TransactionKey {
            scope: DnsScope::from_packet(packet),
            client: client.clone(),
            client_port,
            id: message.id,
        };
        let exchange = self.exchanges.get(&key)?.entries.iter().find(|entry| {
            if message.response {
                entry.reply.as_ref().is_some_and(|reply| {
                    reply.first.packet == packet.no
                        || reply.alternates.iter().any(|other| other.packet == packet.no)
                })
            } else {
                entry.query.packet_no == packet.no
            }
        })?;
        let mut replies = Vec::new();
        let mut additional_replies_omitted = false;
        if let Some(reply) = &exchange.reply {
            replies.push(reply.first.clone());
            replies.extend(reply.alternates.iter().cloned());
            additional_replies_omitted = reply.alternates_omitted;
        }
        Some(DnsExchangeEvidence {
            transaction_id: message.id,
            question: exchange.query.question.name.clone(),
            query_type: exchange.query.question.qtype,
            query_class: exchange.query.question.qclass,
            query_packet: exchange.query.packet_no,
            client: client.clone(),
            client_port,
            expected_resolver: exchange.query.server.clone(),
            replies,
            additional_replies_omitted,
        })
    }
}
