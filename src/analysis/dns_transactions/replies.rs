use sha2::{Digest, Sha256};

use super::{DnsFinding, DnsFindingKind, DnsMessage, DnsReplyEvidence, PendingQuery, answers, append_evidence};
use crate::net::packet::Packet;

const MAX_ALTERNATE_REPLIES: usize = 8;

#[derive(Debug)]
pub(super) struct RecentResponse {
    pub(super) first: DnsReplyEvidence,
    pub(super) timestamp: f64,
    pub(super) alternates: Vec<AlternateResponse>,
    pub(super) alternates_omitted: bool,
    fingerprint: [u8; 32],
    baseline: Option<ComparisonBaseline>,
}

#[derive(Debug)]
pub(super) struct AlternateResponse {
    pub(super) evidence: DnsReplyEvidence,
    fingerprint: [u8; 32],
}

#[derive(Debug)]
struct ComparisonBaseline {
    packet: u64,
    frames: Vec<u64>,
    resolver: String,
    truncated: bool,
    answer_fingerprint: Option<answers::AnswerFingerprint>,
}

impl ComparisonBaseline {
    fn new(packet: &Packet, message: &DnsMessage<'_>) -> Self {
        Self {
            packet: packet.no,
            frames: message.frames.to_vec(),
            resolver: packet.src.clone(),
            truncated: message.truncated(),
            answer_fingerprint: answers::answer_fingerprint(message),
        }
    }
}

pub(super) enum ReplyOutcome {
    Inspect(Option<DnsFinding>),
    Repeat,
    Finding(DnsFinding),
}

impl RecentResponse {
    pub(super) fn new(packet: &Packet, message: &DnsMessage<'_>, question_matches: bool) -> Self {
        Self {
            first: DnsReplyEvidence::from_reply(packet, message),
            fingerprint: Sha256::digest(message.bytes).into(),
            timestamp: packet.timestamp,
            baseline: question_matches.then(|| ComparisonBaseline::new(packet, message)),
            alternates: Vec::new(),
            alternates_omitted: false,
        }
    }

    pub(super) fn observe_follow_up(
        &mut self,
        packet: &Packet,
        query: &PendingQuery,
        message: &DnsMessage<'_>,
    ) -> ReplyOutcome {
        let fingerprint = Sha256::digest(message.bytes).into();
        if (self.fingerprint == fingerprint && self.first.resolver == packet.src)
            || self.alternates.iter().any(|reply| {
                reply.fingerprint == fingerprint && reply.evidence.resolver == packet.src
            })
        {
            return ReplyOutcome::Repeat;
        }
        if query.question != message.question {
            self.retain(packet, message, fingerprint, false);
            return ReplyOutcome::Finding(question_mismatch(query, message));
        }
        let Some(baseline) = &self.baseline else {
            self.baseline = Some(ComparisonBaseline::new(packet, message));
            self.retain(packet, message, fingerprint, true);
            return ReplyOutcome::Inspect(None);
        };

        // TC indicates a partial response (RFC 2181, section 9), not an answer change.
        if baseline.resolver == packet.src && (baseline.truncated || message.truncated()) {
            let promote = baseline.truncated && !message.truncated();
            if promote {
                self.baseline = Some(ComparisonBaseline::new(packet, message));
            }
            self.retain(packet, message, fingerprint, promote);
            return if promote && query.server == packet.src {
                ReplyOutcome::Inspect(None)
            } else {
                ReplyOutcome::Repeat
            };
        }

        let (kind, detail) = if baseline.resolver != packet.src {
            (
                DnsFindingKind::ConflictingResponse,
                format!("competing replies from {} and {}", baseline.resolver, packet.src),
            )
        } else {
            let (kind, difference) = match (
                baseline.answer_fingerprint.as_ref(),
                answers::answer_fingerprint(message),
            ) {
                (Some(before), Some(after)) if before.rcode != after.rcode => (
                    DnsFindingKind::ChangedAnswerSet,
                    format!("a different response code ({} to {})", before.rcode, after.rcode),
                ),
                (Some(before), Some(after)) if before.digest.is_some() && before.digest == after.digest => {
                    return ReplyOutcome::Repeat;
                }
                (Some(before), Some(after)) if before.digest.is_some() && after.digest.is_some() => (
                    DnsFindingKind::ChangedAnswerSet,
                    "a different answer set".into(),
                ),
                _ => (
                    DnsFindingKind::ChangedReply,
                    "different reply bytes; answer comparison unavailable".into(),
                ),
            };
            (kind, format!("{difference} from resolver {}", baseline.resolver))
        };
        let mut related_packets = vec![query.packet_no, baseline.packet];
        append_evidence(&mut related_packets, &baseline.frames);
        let expected_resolver_arrived = baseline.resolver != query.server && packet.src == query.server;
        let finding = DnsFinding {
            kind,
            detail: format!(
                "transaction 0x{:04x} for {} received {detail}",
                message.id, query.question.name,
            ),
            related_packets,
        };
        if expected_resolver_arrived {
            self.baseline = Some(ComparisonBaseline::new(packet, message));
        }
        self.retain(packet, message, fingerprint, expected_resolver_arrived);
        if expected_resolver_arrived {
            ReplyOutcome::Inspect(Some(finding))
        } else {
            ReplyOutcome::Finding(finding)
        }
    }

    fn retain(
        &mut self,
        packet: &Packet,
        message: &DnsMessage<'_>,
        fingerprint: [u8; 32],
        first_match: bool,
    ) {
        if self.first.packet == packet.no
            || self.alternates.iter().any(|reply| reply.evidence.packet == packet.no)
        {
            return;
        }
        if self.alternates.len() == MAX_ALTERNATE_REPLIES {
            self.alternates_omitted = true;
            if !first_match {
                return;
            }
            self.alternates.pop();
        }
        self.alternates.push(AlternateResponse {
            evidence: DnsReplyEvidence::from_reply(packet, message),
            fingerprint,
        });
    }
}

pub(super) fn question_mismatch(query: &PendingQuery, message: &DnsMessage<'_>) -> DnsFinding {
    DnsFinding {
        kind: DnsFindingKind::QuestionMismatch,
        related_packets: vec![query.packet_no],
        detail: format!(
            "transaction 0x{:04x} expected {} (type {}, class {}) but reply echoed {} (type {}, class {})",
            message.id, query.question.name, query.question.qtype, query.question.qclass,
            message.question.name, message.question.qtype, message.question.qclass,
        ),
    }
}
