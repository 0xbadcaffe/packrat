use super::*;
use super::scans::scan_scope;
use crate::net::recent_evidence::RecentEvidence;
use std::collections::BTreeMap;

const WINDOW_SECS: u64 = 300;
const TARGET_THRESHOLD: usize = 3;
const MAX_TARGETS: usize = 256;
const SIGNATURE: &str = "NTLM authentication fan-out";

#[derive(Default)]
struct SourceState {
    targets: BTreeMap<String, (f64, u64)>,
    last_seen: f64,
    alerted: bool,
}

#[derive(Default)]
pub(super) struct NtlmFanout {
    sources: HashMap<(String, ScanScope), SourceState>,
    evidence: RecentEvidence<512, WINDOW_SECS>,
}

impl SecurityEngine {
    pub(super) fn check_ntlm_fanout(&mut self, pkt: &Packet, archive_rules: Option<&[String]>) {
        let (Some(source_port), Some(445)) = (pkt.src_port, pkt.dst_port) else { return };
        if !pkt.timestamp.is_finite()
            || !is_internal_address(&pkt.src)
            || !is_internal_address(&pkt.dst)
            || !crate::analysis::stream::tcp_payload_with_ack(pkt, (source_port, 445))
                .is_some_and(|(_, payload)| smb_wire::has_ntlm_authenticate(payload))
        {
            return;
        }
        let window = WINDOW_SECS as f64;
        let scope = scan_scope(pkt);
        let tracker = &mut self.ntlm_fanout;
        tracker.sources.retain(|_, state| pkt.timestamp - state.last_seen <= window);
        let key = (pkt.src.clone(), scope);
        if tracker.sources.len() >= MAX_SCAN_STATES && !tracker.sources.contains_key(&key) {
            return;
        }
        let state = tracker.sources.entry(key).or_default();
        state.last_seen = if state.targets.is_empty() { pkt.timestamp } else { state.last_seen.max(pkt.timestamp) };
        if state.last_seen - pkt.timestamp > window {
            return;
        }
        state.targets.retain(|_, (seen, _)| state.last_seen - *seen <= window);
        if state.targets.len() <= TARGET_THRESHOLD / 2 {
            state.alerted = false;
        }
        let sample = (pkt.timestamp, pkt.no);
        if let Some(prior) = state.targets.get_mut(&pkt.dst) {
            if pkt.timestamp <= prior.0 { return; }
            *prior = sample;
        } else if state.targets.len() < MAX_TARGETS {
            state.targets.insert(pkt.dst.clone(), sample);
        } else {
            return;
        }
        let retain = archive_rules.is_some_and(|rules| {
            crate::analysis::alert_provenance::rule_id_for("IDS", SIGNATURE)
                .is_some_and(|id| rules.iter().any(|rule| rule == id))
        });
        let count = state.targets.len();
        if count < TARGET_THRESHOLD || state.alerted {
            if retain { tracker.evidence.remember(pkt); }
            return;
        }
        state.alerted = true;
        let related_packets: Vec<_> = state.targets.values().map(|&(_, frame)| frame)
            .filter(|&frame| frame != pkt.no).collect();
        if retain {
            // Sample times were validated against the source watermark, not the trigger timestamp.
            self.findings.retained_evidence.extend(related_packets.iter()
                .filter_map(|&frame| tracker.evidence.cited_packet(pkt, frame).cloned()));
            tracker.evidence.remember(pkt);
        }
        self.push_ids_finding(IdsFinding {
            alert: IdsAlert {
                pkt_no: pkt.no,
                signature: SIGNATURE,
                severity: Severity::Medium,
                detail: format!("{} sent SMB2 NTLM authentication to {count} internal hosts within 5 minutes; outcomes unverified", pkt.src),
            },
            related_packets,
            correlation_key: Some(format!("{scope:?}:{}:episode:{}", pkt.src, pkt.no)),
        });
    }
}
