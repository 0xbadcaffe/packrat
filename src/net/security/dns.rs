use super::*;
use crate::analysis::{dns_transactions, stream::DnsTcpObservation};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;

const TUNNEL_WINDOW_SECS: f64 = 60.0;
const TUNNEL_THRESHOLD: usize = 8;
const MAX_GROUPS: usize = 1024;
const MAX_SAMPLES: usize = 32;
const MAX_FRAMES_PER_QUERY: usize =
    (crate::analysis::alert_center::MAX_ALERT_PACKET_REFS - 1) / TUNNEL_THRESHOLD;

#[derive(Hash, Eq, PartialEq)]
struct TunnelKey {
    scope: ServiceScope,
    client: String,
    resolver: String,
    suffix: String,
    transport: &'static str,
}

struct QuerySample {
    name_digest: [u8; 32],
    timestamp: f64,
    frames: Vec<u64>,
    frames_sampled: bool,
    entropy: f64,
    label_length: usize,
}

#[derive(Default)]
struct TunnelWindow {
    last_seen: f64,
    samples: VecDeque<QuerySample>,
    alerted: bool,
}

#[derive(Default)]
pub(super) struct DnsTunnelTracker {
    groups: HashMap<TunnelKey, TunnelWindow>,
}

impl DnsTunnelTracker {
    pub(super) fn clear(&mut self) {
        self.groups.clear();
    }

    fn observe(
        &mut self, pkt: &Packet, name: &str, transport: &'static str, frames: &[u64],
    ) -> Option<(DnsTunnelSuspect, IdsFinding)> {
        let now = pkt.timestamp;
        if frames.is_empty() {
            return None;
        }
        if !name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')) {
            return None;
        }
        let suffix = psl::domain_str(name)?;
        let prefix = name.strip_suffix(suffix)?.strip_suffix('.')?;
        let (label_length, entropy) = prefix.split('.').filter(|label| label.len() >= 24)
            .map(|label| (label.len(), shannon_entropy(label.as_bytes())))
            .max_by(|a, b| a.1.total_cmp(&b.1)).filter(|&(_, entropy)| entropy >= 3.5)?;
        let scope = service_scope(pkt);
        let key = TunnelKey { scope, client: pkt.src.clone(), resolver: pkt.dst.clone(), suffix: suffix.into(), transport };
        if self.groups.len() >= MAX_GROUPS && !self.groups.contains_key(&key) {
            self.groups.retain(|_, group| now - group.last_seen <= TUNNEL_WINDOW_SECS);
            if self.groups.len() >= MAX_GROUPS { return None; }
        }
        let window = self.groups.entry(key).or_default();
        if now < window.last_seen { return None; }
        window.last_seen = now;
        window.samples.retain(|sample| now - sample.timestamp <= TUNNEL_WINDOW_SECS);
        if window.samples.len() <= TUNNEL_THRESHOLD / 2 { window.alerted = false; }
        let name_digest = Sha256::digest(prefix.as_bytes()).into();
        if window.samples.iter().any(|sample| sample.name_digest == name_digest) {
            return None;
        }
        if window.samples.len() == MAX_SAMPLES { window.samples.pop_front(); }
        let frames_sampled = frames.len() > MAX_FRAMES_PER_QUERY;
        let frames = if frames_sampled {
            let leading = MAX_FRAMES_PER_QUERY / 2;
            let trailing = MAX_FRAMES_PER_QUERY - leading;
            frames[..leading].iter().chain(&frames[frames.len() - trailing..]).copied().collect()
        } else {
            frames.to_vec()
        };
        window.samples.push_back(QuerySample {
            name_digest, timestamp: now, frames, frames_sampled, entropy, label_length,
        });
        if window.samples.len() < TUNNEL_THRESHOLD || window.alerted { return None; }
        window.alerted = true;
        let count = window.samples.len();
        let max_entropy = window.samples.iter().map(|sample| sample.entropy).fold(0.0, f64::max);
        let max_subdomain_len = window.samples.iter().map(|sample| sample.label_length).max().unwrap_or(0);
        let mut related_packets: Vec<_> = window.samples.iter().flat_map(|sample| sample.frames.iter().copied())
            .filter(|&frame| frame != pkt.no).collect();
        related_packets.sort_unstable();
        related_packets.dedup();
        let evidence_note = if window.samples.iter().any(|sample| sample.frames_sampled) {
            "; contributing frame references sampled"
        } else {
            ""
        };
        Some((
            DnsTunnelSuspect { apex: suffix.into(), query_count: count as u64, max_entropy,
                max_subdomain_len, unique_subdomains: count, score: count as f64 },
            IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: "DNS tunnel behavior",
                    severity: Severity::Medium,
                    detail: format!(
                        "{count} distinct {transport} queries with long, high-entropy labels under {suffix} from {} to {} in 60 seconds; tunneling and data transfer unverified{evidence_note}",
                        pkt.src, pkt.dst,
                    ),
                },
                related_packets,
                correlation_key: Some(format!("{scope:?}:{transport}:{}>{}:{suffix}:{}", pkt.src, pkt.dst, pkt.no)),
            },
        ))
    }
}

impl SecurityEngine {
    pub(super) fn check_dns_tunnel(&mut self, pkt: &Packet, tcp: &DnsTcpObservation) {
        if pkt.dst_port != Some(53) || !pkt.timestamp.is_finite() || pkt.timestamp < 0.0
            || pkt.capture.as_ref().is_some_and(|capture| capture.link_type != 1)
        {
            return;
        }
        match tcp {
            DnsTcpObservation::Anchored { destination: 53, records, .. } => {
                for record in records {
                    if let Some(name) = dns_transactions::query_name_from_message(&record.bytes) {
                        self.observe_encoded_dns_query(pkt, &name, "TCP", &record.frames);
                    }
                }
            }
            DnsTcpObservation::Unanchored => {
                if let Some(name) = dns_transactions::wire_query_name(pkt) {
                    self.observe_encoded_dns_query(pkt, &name, "UDP", &[pkt.no]);
                }
            }
            _ => {}
        }
    }

    fn observe_encoded_dns_query(&mut self, pkt: &Packet, name: &str, transport: &'static str, frames: &[u64]) {
        if let Some((suspect, finding)) = self.dns_tunnel.observe(pkt, name, transport, frames) {
            if self.dns_suspects.len() >= MAX_ENTRIES { self.dns_suspects.remove(0); }
            self.dns_suspects.push(suspect);
            self.push_ids_finding(finding);
        }
    }

    // ─── Byte pattern helpers ─────────────────────────────────────────────────

    pub(super) fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    pub(super) fn contains_str_ci(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
    }

    pub(super) fn nop_sled_16(data: &[u8]) -> bool {
        let mut run = 0usize;
        for &b in data {
            if b == 0x90 {
                run += 1;
                if run >= 16 {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        false
    }

    pub(super) fn count_pattern_ascii(data: &[u8], pattern: &[u8]) -> usize {
        if pattern.is_empty() || data.len() < pattern.len() {
            return 0;
        }
        data.windows(pattern.len())
            .filter(|w| *w == pattern)
            .count()
    }

}
