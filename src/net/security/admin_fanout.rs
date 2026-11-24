use std::collections::BTreeMap;

use super::*;
use crate::net::recent_evidence::RecentEvidence;

const SYN_TIMEOUT: f64 = 15.0;
const FANOUT_WINDOW: f64 = 60.0;
const MAX_PENDING: usize = 2048;
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
    expected_ack: u32,
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
    pending: HashMap<SynKey, PendingSyn>,
    responders: HashMap<(ServiceScope, String, u16), RespondedTargets>,
    // A cited SYN may precede the oldest in-window reply by the full SYN timeout.
    evidence: RecentEvidence<1024, 75>,
}

impl AdminFanout {
    pub(super) fn clear(&mut self) {
        self.pending.clear();
        self.responders.clear();
        self.evidence = Default::default();
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
                expected_ack: tcp.sequence.wrapping_add(1),
            };
            let sample = SynSample { at: now, frame: pkt.no };
            let accepted = if let Some(pending) = self.pending.get_mut(&key) {
                pending.retry(sample)
            } else {
                if self.pending.len() >= MAX_PENDING {
                    self.pending.retain(|_, pending| now - pending.latest.at <= SYN_TIMEOUT);
                }
                if self.pending.len() < MAX_PENDING {
                    self.pending.insert(key, PendingSyn::new(sample));
                    true
                } else {
                    false
                }
            };
            if accepted && retains_evidence(archive_rules) {
                self.evidence.remember(pkt);
            }
            return None;
        }
        let key = SynKey {
            scope,
            client: (pkt.dst.clone(), tcp.destination_port),
            server: (pkt.src.clone(), tcp.source_port),
            expected_ack: tcp.acknowledgement,
        };
        let syn = self.pending.get(&key)?.matched_frame(now, pkt.no)?;
        self.pending.remove(&key);
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
