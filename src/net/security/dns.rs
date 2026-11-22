use super::*;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;

const TUNNEL_WINDOW_SECS: f64 = 60.0;
const TUNNEL_THRESHOLD: usize = 8;
const MAX_GROUPS: usize = 1024;
const MAX_SAMPLES: usize = 32;

#[derive(Hash, Eq, PartialEq)]
struct TunnelKey {
    scope: ServiceScope,
    client: String,
    resolver: String,
    suffix: String,
}

struct QuerySample {
    name_digest: [u8; 32],
    timestamp: f64,
    frame: u64,
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

    fn observe(&mut self, pkt: &Packet) -> Option<(DnsTunnelSuspect, IdsFinding)> {
        let now = pkt.timestamp;
        if pkt.dst_port != Some(53) || !now.is_finite() || now < 0.0
            || pkt.capture.as_ref().is_some_and(|capture| capture.link_type != 1)
        {
            return None;
        }
        let name = crate::analysis::dns_transactions::wire_query_name(pkt)?;
        if !name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')) {
            return None;
        }
        let (prefix, suffix) = name[..name.rfind('.')?].rfind('.')
            .map(|index| (&name[..index], &name[index + 1..]))?;
        let (label_length, entropy) = prefix.split('.').filter(|label| label.len() >= 24)
            .map(|label| (label.len(), shannon_entropy(label.as_bytes())))
            .max_by(|a, b| a.1.total_cmp(&b.1)).filter(|&(_, entropy)| entropy >= 3.5)?;
        let scope = service_scope(pkt);
        let key = TunnelKey { scope, client: pkt.src.clone(), resolver: pkt.dst.clone(), suffix: suffix.into() };
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
        if window.samples.iter().any(|sample| sample.name_digest == name_digest || sample.frame == pkt.no) {
            return None;
        }
        if window.samples.len() == MAX_SAMPLES { window.samples.pop_front(); }
        window.samples.push_back(QuerySample { name_digest, timestamp: now, frame: pkt.no, entropy, label_length });
        if window.samples.len() < TUNNEL_THRESHOLD || window.alerted { return None; }
        window.alerted = true;
        let count = window.samples.len();
        let max_entropy = window.samples.iter().map(|sample| sample.entropy).fold(0.0, f64::max);
        let max_subdomain_len = window.samples.iter().map(|sample| sample.label_length).max().unwrap_or(0);
        Some((
            DnsTunnelSuspect { apex: suffix.into(), query_count: count as u64, max_entropy,
                max_subdomain_len, unique_subdomains: count, score: count as f64 },
            IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: "DNS tunnel behavior",
                    severity: Severity::Medium,
                    detail: format!(
                        "{count} distinct queries with long, high-entropy labels under {suffix} from {} to {} in 60 seconds; tunneling and data transfer unverified",
                        pkt.src, pkt.dst,
                    ),
                },
                related_packets: window.samples.iter().map(|sample| sample.frame)
                    .filter(|&frame| frame != pkt.no).collect(),
                correlation_key: Some(format!("{scope:?}:{}>{}:{suffix}:{}", pkt.src, pkt.dst, pkt.no)),
            },
        ))
    }
}

impl SecurityEngine {
    pub(super) fn check_dns_tunnel(&mut self, pkt: &Packet) {
        if let Some((suspect, finding)) = self.dns_tunnel.observe(pkt) {
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
