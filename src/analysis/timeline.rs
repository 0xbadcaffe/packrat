//! Flow timeline — per-second/per-minute packet and byte counts for graphing.

use crate::net::packet::Packet;

// ─── Bucket ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct Bucket {
    pub ts:    f64,   // bucket start time (unix seconds, floored to bucket_secs)
    pub pkts:  u64,
    pub bytes: u64,
}

// ─── Timeline ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Timeline {
    pub bucket_secs: u64,
    pub max_buckets: usize,
    pub buckets:     Vec<Bucket>,
}

impl Timeline {
    pub fn new(bucket_secs: u64, max_buckets: usize) -> Self {
        Self { bucket_secs, max_buckets, buckets: Vec::new() }
    }

    pub fn ingest(&mut self, pkt: &Packet) {
        let bucket_ts = (pkt.timestamp as u64 / self.bucket_secs * self.bucket_secs) as f64;
        if let Some(b) = self.buckets.last_mut() {
            if (b.ts - bucket_ts).abs() < 0.001 {
                b.pkts  += 1;
                b.bytes += pkt.length as u64;
                return;
            }
        }
        // New bucket
        self.buckets.push(Bucket { ts: bucket_ts, pkts: 1, bytes: pkt.length as u64 });
        if self.buckets.len() > self.max_buckets {
            self.buckets.remove(0);
        }
    }

    pub fn max_pkts(&self) -> u64 { self.buckets.iter().map(|b| b.pkts).max().unwrap_or(1) }
    pub fn max_bytes(&self) -> u64 { self.buckets.iter().map(|b| b.bytes).max().unwrap_or(1) }

    pub fn clear(&mut self) { self.buckets.clear(); }

    /// Last N buckets (for a fixed-width sparkline).
    pub fn last_n(&self, n: usize) -> &[Bucket] {
        let len = self.buckets.len();
        if len <= n { &self.buckets } else { &self.buckets[len - n..] }
    }
}

impl Default for Timeline {
    fn default() -> Self { Self::new(1, 300) } // 1-second buckets, 5-minute window
}

// ─── Per-protocol timeline ─────────────────────────────────────────────────────

/// Maintains separate timelines for top protocols.
#[derive(Debug, Default)]
pub struct ProtocolTimelines {
    pub global: Timeline,
    pub by_proto: std::collections::HashMap<String, Timeline>,
}

impl ProtocolTimelines {
    pub fn ingest(&mut self, pkt: &Packet) {
        self.global.ingest(pkt);
        self.by_proto
            .entry(pkt.protocol.clone())
            .or_insert_with(|| Timeline::new(1, 300))
            .ingest(pkt);
    }

    pub fn top_protocols(&self, n: usize) -> Vec<(&str, u64)> {
        let mut totals: Vec<(&str, u64)> = self.by_proto.iter()
            .map(|(k, v)| (k.as_str(), v.buckets.iter().map(|b| b.pkts).sum()))
            .collect();
        totals.sort_by(|a, b| b.1.cmp(&a.1));
        totals.truncate(n);
        totals
    }

    pub fn clear(&mut self) {
        self.global.clear();
        self.by_proto.clear();
    }
}
