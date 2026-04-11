//! Differential PCAP analysis — compare two sets of packets.
//!
//! Finds packets unique to each side, plus protocol/host deltas.

use std::collections::{HashMap, HashSet};
use crate::net::packet::Packet;

// ─── Diff result ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PacketDiff {
    /// Packets only in baseline (removed).
    pub only_in_a: Vec<u64>,
    /// Packets only in compare (added).
    pub only_in_b: Vec<u64>,
    /// Protocol count deltas: proto → (a_count, b_count).
    pub proto_delta: HashMap<String, (u64, u64)>,
    /// Host deltas: ip → (a_bytes, b_bytes).
    pub host_delta:  HashMap<String, (u64, u64)>,
    /// Port deltas: port → (a_count, b_count).
    pub port_delta:  HashMap<u16, (u64, u64)>,
    /// Total packets in A.
    pub total_a: usize,
    /// Total packets in B.
    pub total_b: usize,
}

impl PacketDiff {
    /// Summary as a short string.
    pub fn summary(&self) -> String {
        let added   = self.only_in_b.len();
        let removed = self.only_in_a.len();
        let proto_changes: Vec<String> = self.proto_delta.iter()
            .filter(|(_, (a, b))| a != b)
            .map(|(p, (a, b))| format!("{p}: {a}→{b}"))
            .take(5)
            .collect();
        format!(
            "+{added} -{removed} packets | {} total→{} | proto changes: {}",
            self.total_a, self.total_b,
            if proto_changes.is_empty() { "none".into() } else { proto_changes.join(", ") }
        )
    }
}

// ─── Diff engine ──────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct DiffEngine {
    /// Snapshot A (baseline) by frame fingerprint.
    snap_a: HashMap<String, u64>,
    /// Snapshot B (compare) by frame fingerprint.
    snap_b: HashMap<String, u64>,
    pub result: Option<PacketDiff>,
}

impl DiffEngine {
    /// Load packet set A (baseline).
    pub fn load_a(&mut self, packets: &[Packet]) {
        self.snap_a.clear();
        for pkt in packets {
            let fp = fingerprint(pkt);
            self.snap_a.insert(fp, pkt.no);
        }
    }

    /// Load packet set B (compare target).
    pub fn load_b(&mut self, packets: &[Packet]) {
        self.snap_b.clear();
        for pkt in packets {
            let fp = fingerprint(pkt);
            self.snap_b.insert(fp, pkt.no);
        }
    }

    pub fn compute(&mut self, a_packets: &[Packet], b_packets: &[Packet]) {
        let fps_a: HashSet<&String> = self.snap_a.keys().collect();
        let fps_b: HashSet<&String> = self.snap_b.keys().collect();

        let only_in_a: Vec<u64> = fps_a.difference(&fps_b)
            .filter_map(|fp| self.snap_a.get(*fp).copied())
            .collect();
        let only_in_b: Vec<u64> = fps_b.difference(&fps_a)
            .filter_map(|fp| self.snap_b.get(*fp).copied())
            .collect();

        // Protocol deltas
        let mut proto_delta: HashMap<String, (u64, u64)> = HashMap::new();
        for pkt in a_packets {
            proto_delta.entry(pkt.protocol.clone()).or_default().0 += 1;
        }
        for pkt in b_packets {
            proto_delta.entry(pkt.protocol.clone()).or_default().1 += 1;
        }

        // Host deltas (by src)
        let mut host_delta: HashMap<String, (u64, u64)> = HashMap::new();
        for pkt in a_packets {
            host_delta.entry(pkt.src.clone()).or_default().0 += pkt.length as u64;
        }
        for pkt in b_packets {
            host_delta.entry(pkt.src.clone()).or_default().1 += pkt.length as u64;
        }

        // Port deltas
        let mut port_delta: HashMap<u16, (u64, u64)> = HashMap::new();
        for pkt in a_packets {
            if let Some(p) = pkt.dst_port {
                port_delta.entry(p).or_default().0 += 1;
            }
        }
        for pkt in b_packets {
            if let Some(p) = pkt.dst_port {
                port_delta.entry(p).or_default().1 += 1;
            }
        }

        self.result = Some(PacketDiff {
            only_in_a,
            only_in_b,
            proto_delta,
            host_delta,
            port_delta,
            total_a: a_packets.len(),
            total_b: b_packets.len(),
        });
    }

    pub fn clear(&mut self) {
        self.snap_a.clear();
        self.snap_b.clear();
        self.result = None;
    }
}

/// Stable fingerprint: protocol + src + dst + ports + length.
/// Does NOT use timestamp (we want structural equivalence, not time equality).
fn fingerprint(pkt: &Packet) -> String {
    format!("{}-{}-{}-{:?}-{:?}-{}",
        pkt.protocol, pkt.src, pkt.dst, pkt.src_port, pkt.dst_port, pkt.length)
}
