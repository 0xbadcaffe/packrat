use std::collections::BTreeMap;

use super::*;
use crate::net::flow::acknowledges_syn;
use crate::net::recent_evidence::RecentEvidence;

const SYN_TIMEOUT: f64 = 15.0;
const FANOUT_WINDOW: f64 = 60.0;
const MAX_PENDING: usize = 2048;
const MAX_PENDING_PER_TUPLE: usize = 8;
const MAX_TARGETS: usize = 64;
const REARM_TARGETS: usize = LATERAL_TARGET_THRESHOLD / 2;
const INITIAL_SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;
const SIGNATURE: &str = "Administrative service response fan-out";

fn retains_evidence(rules: Option<&[String]>) -> bool {
    rules.is_some_and(|rules| crate::analysis::alert_provenance::rule_id_for("IDS", SIGNATURE)
        .is_some_and(|id| rules.iter().any(|rule| rule == id)))
}

#[derive(PartialEq, Eq, Hash)]
struct SynKey {
    scope: ServiceScope,
    client: (String, u16),
    server: (String, u16),
}

struct SynAttempt {
    sequence: u32,
    payload_length: u32,
    samples: PendingSyn,
}

#[derive(Default)]
struct PendingTuple {
    attempts: Vec<SynAttempt>,
    overflow_at: Option<f64>,
}

#[derive(Clone, Copy)]
struct SynSample {
    at: f64,
    frame: u64,
}

struct PendingSyn {
    first: SynSample,
    latest: SynSample,
}

impl PendingSyn {
    fn new(sample: SynSample) -> Self {
        Self { first: sample, latest: sample }
    }

    fn retry(&mut self, sample: SynSample) -> bool {
        if sample.frame <= self.latest.frame || sample.at < self.latest.at {
            return false;
        }
        if sample.at - self.first.at > SYN_TIMEOUT {
            self.first = if sample.at - self.latest.at <= SYN_TIMEOUT { self.latest } else { sample };
        }
        self.latest = sample;
        true
    }

    fn matched_frame(&self, at: f64, frame: u64) -> Option<u64> {
        [self.first, self.latest].into_iter().find(|syn| {
            syn.frame < frame && (0.0..=SYN_TIMEOUT).contains(&(at - syn.at))
        }).map(|syn| syn.frame)
    }
}

#[derive(Default)]
struct RespondedTargets {
    targets: BTreeMap<String, (f64, [u64; 2])>,
    last_seen: Option<f64>,
    alerted: bool,
}

#[derive(Default)]
pub(super) struct AdminFanout {
    pending: HashMap<SynKey, PendingTuple>,
    pending_count: usize,
    untracked_at: Option<f64>,
    responders: HashMap<(ServiceScope, String, u16), RespondedTargets>,
    // A cited SYN may precede the oldest in-window reply by the full SYN timeout.
    evidence: RecentEvidence<1024, 75>,
}

impl AdminFanout {
    pub(super) fn clear(&mut self) {
        self.pending.clear();
        self.pending_count = 0;
        self.untracked_at = None;
        self.responders.clear();
        self.evidence = Default::default();
    }

    fn remember_syn(&mut self, key: SynKey, tcp: TcpSignal, sample: SynSample) -> bool {
        if let Some(tuple) = self.pending.get_mut(&key) {
            if let Some(attempt) = tuple.attempts.iter_mut().find(|attempt| {
                (attempt.sequence, attempt.payload_length) == (tcp.sequence, tcp.payload_length)
            }) {
                return attempt.samples.retry(sample);
            }
        }
        if self.pending_count >= MAX_PENDING {
            self.pending_count = 0;
            self.pending.retain(|_, tuple| {
                tuple.attempts.retain(|attempt| sample.at - attempt.samples.latest.at <= SYN_TIMEOUT);
                self.pending_count += tuple.attempts.len();
                if tuple.attempts.is_empty()
                    && let Some(at) = tuple.overflow_at.filter(|at| sample.at - at <= SYN_TIMEOUT)
                {
                    self.untracked_at = Some(self.untracked_at.map_or(at, |latest| latest.max(at)));
                }
                !tuple.attempts.is_empty()
            });
            if self.pending_count >= MAX_PENDING {
                let overflow = self.pending.get_mut(&key).map_or(&mut self.untracked_at, |tuple| &mut tuple.overflow_at);
                *overflow = Some(overflow.map_or(sample.at, |at| at.max(sample.at)));
                return false;
            }
        }
        let tuple = self.pending.entry(key).or_default();
        let attempts = &mut tuple.attempts;
        let before = attempts.len();
        attempts.retain(|attempt| sample.at - attempt.samples.latest.at <= SYN_TIMEOUT);
        self.pending_count -= before - attempts.len();
        if attempts.len() >= MAX_PENDING_PER_TUPLE {
            tuple.overflow_at = Some(tuple.overflow_at.map_or(sample.at, |at| at.max(sample.at)));
            return false;
        }
        attempts.push(SynAttempt {
            sequence: tcp.sequence, payload_length: tcp.payload_length, samples: PendingSyn::new(sample),
        });
        self.pending_count += 1;
        true
    }

    fn take_unique_syn(&mut self, key: &SynKey, reply: &Packet, acknowledgement: u32) -> Option<u64> {
        let tuple = self.pending.get_mut(key)?;
        // A dropped attempt might also match this reply.
        if [self.untracked_at, tuple.overflow_at].into_iter().flatten()
            .any(|at| reply.timestamp - at <= SYN_TIMEOUT)
        {
            return None;
        }
        let attempts = &mut tuple.attempts;
        let mut matches = attempts.iter().enumerate().filter_map(|(index, attempt)| {
            if !acknowledges_syn(attempt.sequence, attempt.payload_length, acknowledgement) {
                return None;
            }
            Some((index, attempt.samples.matched_frame(reply.timestamp, reply.no)?))
        });
        let (index, frame) = matches.next()?;
        if matches.next().is_some() { return None; }
        attempts.swap_remove(index);
        self.pending_count -= 1;
        if attempts.is_empty() { self.pending.remove(key); }
        Some(frame)
    }

    fn observe(&mut self, pkt: &Packet, tcp: TcpSignal, archive_rules: Option<&[String]>) -> Option<IdsFinding> {
        let control = tcp.flags & 0x3f;
        let admin_port = match control {
            INITIAL_SYN => tcp.destination_port,
            SYN_ACK => tcp.source_port,
            _ => return None,
        };
        if !pkt.timestamp.is_finite() || !tcp.complete || !matches!(admin_port, 22 | 135 | 139 | 445 | 3389 | 5985 | 5986)
            || !is_internal_address(&pkt.src) || !is_internal_address(&pkt.dst)
        {
            return None;
        }
        let scope = service_scope(pkt);
        let now = pkt.timestamp;
        if control == INITIAL_SYN {
            let key = SynKey {
                scope,
                client: (pkt.src.clone(), tcp.source_port),
                server: (pkt.dst.clone(), tcp.destination_port),
            };
            let sample = SynSample { at: now, frame: pkt.no };
            let accepted = self.remember_syn(key, tcp, sample);
            if accepted && retains_evidence(archive_rules) {
                self.evidence.remember(pkt);
            }
            return None;
        }
        let key = SynKey {
            scope,
            client: (pkt.dst.clone(), tcp.destination_port),
            server: (pkt.src.clone(), tcp.source_port),
        };
        let syn = self.take_unique_syn(&key, pkt, tcp.acknowledgement)?;
        if retains_evidence(archive_rules) {
            self.evidence.remember(pkt);
        }
        self.record_pair(pkt, scope, admin_port, syn)
    }

    fn record_pair(&mut self, reply: &Packet, scope: ServiceScope, port: u16, syn: u64) -> Option<IdsFinding> {
        let now = reply.timestamp;
        self.responders.retain(|_, state| state.last_seen.is_some_and(|seen| now - seen <= FANOUT_WINDOW));
        let key = (scope, reply.dst.clone(), port);
        if self.responders.len() >= MAX_SCAN_STATES && !self.responders.contains_key(&key) {
            return None;
        }
        let state = self.responders.entry(key).or_default();
        let newest = state.last_seen.map_or(now, |seen| seen.max(now));
        if newest - now > FANOUT_WINDOW {
            return None;
        }
        state.last_seen = Some(newest);
        state.targets.retain(|_, (seen, _)| newest - *seen <= FANOUT_WINDOW);
        // A small drop near the threshold should not split sustained activity into new alerts.
        if state.targets.len() <= REARM_TARGETS {
            state.alerted = false;
        }
        if let Some(sample) = state.targets.get_mut(&reply.src) {
            if sample.0 <= now {
                *sample = (now, [syn, reply.no]);
            }
        } else if state.targets.len() < MAX_TARGETS {
            state.targets.insert(reply.src.clone(), (now, [syn, reply.no]));
        }
        let count = state.targets.len();
        if count < LATERAL_TARGET_THRESHOLD || state.alerted {
            return None;
        }
        state.alerted = true;
        Some(IdsFinding {
            alert: IdsAlert {
                pkt_no: reply.no,
                signature: SIGNATURE,
                severity: Severity::Medium,
                detail: format!(
                    "{} received matching TCP SYN-ACKs from {count} internal hosts on port {port} within 60 seconds; connection and login outcomes unverified",
                    reply.dst,
                ),
            },
            related_packets: state.targets.values().flat_map(|&(_, pair)| pair)
                .filter(|&frame| frame != reply.no).collect(),
            correlation_key: Some(format!("{scope:?}:{}:{port}:episode:{}", reply.dst, reply.no)),
        })
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/admin_fanout_tests.rs"]
mod tests;

impl SecurityEngine {
    pub(super) fn record_admin_tcp(&mut self, pkt: &Packet, tcp: TcpSignal, archive_rules: Option<&[String]>) {
        if let Some(finding) = self.admin_fanout.observe(pkt, tcp, archive_rules) {
            if retains_evidence(archive_rules) {
                self.findings.retained_evidence.extend(finding.related_packets.iter()
                    .filter_map(|&frame| self.admin_fanout.evidence.cited_packet(pkt, frame).cloned()));
            }
            self.push_ids_finding(finding);
        }
    }
}
