//! TCP/UDP flow tracker with beacon and scan detection.
use std::collections::{HashMap, VecDeque};
use crate::net::packet::Packet;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct FlowKey {
    pub ep1: (String, u16),
    pub ep2: (String, u16),
    pub proto: String,
}

impl FlowKey {
    pub fn from_packet(pkt: &Packet) -> Self {
        let a = (pkt.src.clone(), pkt.src_port.unwrap_or(0));
        let b = (pkt.dst.clone(), pkt.dst_port.unwrap_or(0));
        let (ep1, ep2) = if a <= b { (a, b) } else { (b, a) };
        Self { ep1, ep2, proto: pkt.protocol.clone() }
    }
}

#[derive(Default, Clone)]
pub struct FlowFlags {
    pub beacon:    bool,
    pub large:     bool,
    pub encrypted: bool,
    pub scan:      bool,
}

pub struct Flow {
    pub key:        FlowKey,
    pub packets:    u64,
    pub bytes:      u64,
    pub first_seen: f64,
    pub last_seen:  f64,
    pub flags:      FlowFlags,
    last_ts:        f64,
    pub intervals:  VecDeque<f64>,
}

#[derive(Clone, PartialEq)]
pub enum FlowSort { Bytes, Packets, Time }

pub struct FlowTracker {
    pub flows: HashMap<FlowKey, Flow>,
    scan_seen: HashMap<String, std::collections::HashSet<(String, u16)>>,
}

impl FlowTracker {
    pub fn new() -> Self {
        Self { flows: HashMap::new(), scan_seen: HashMap::new() }
    }

    pub fn update(&mut self, pkt: &Packet) {
        use crate::net::inspector::shannon_entropy;
        let key = FlowKey::from_packet(pkt);
        let flow = self.flows.entry(key.clone()).or_insert_with(|| Flow {
            key: key.clone(),
            packets: 0, bytes: 0,
            first_seen: pkt.timestamp, last_seen: pkt.timestamp,
            flags: FlowFlags::default(),
            last_ts: pkt.timestamp, intervals: VecDeque::new(),
        });
        // Update beacon detection
        let interval = pkt.timestamp - flow.last_ts;
        if interval > 0.001 && flow.last_ts > 0.0 {
            if flow.intervals.len() >= 20 { flow.intervals.pop_front(); }
            flow.intervals.push_back(interval);
            if flow.intervals.len() >= 5 {
                let n = flow.intervals.len() as f64;
                let mean = flow.intervals.iter().sum::<f64>() / n;
                let var = flow.intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
                let cv = if mean > 0.0 { var.sqrt() / mean } else { f64::MAX };
                flow.flags.beacon = cv < 0.15 && mean > 0.5;
            }
        }
        flow.last_ts = pkt.timestamp;
        flow.packets += 1;
        flow.bytes += pkt.length as u64;
        flow.last_seen = pkt.timestamp;
        flow.flags.large = flow.bytes > 1_000_000;
        if pkt.bytes.len() > 20 {
            flow.flags.encrypted = shannon_entropy(&pkt.bytes) > 7.2;
        }
        // Scan detection
        let dst_entry = self.scan_seen.entry(pkt.src.clone()).or_default();
        dst_entry.insert((pkt.dst.clone(), pkt.dst_port.unwrap_or(0)));
        if dst_entry.len() >= 5 {
            // Mark all flows from this source as scan
            for f in self.flows.values_mut() {
                if f.key.ep1.0 == pkt.src || f.key.ep2.0 == pkt.src {
                    f.flags.scan = true;
                }
            }
        }
    }

    pub fn sorted_flows(&self, sort: &FlowSort) -> Vec<&Flow> {
        let mut v: Vec<&Flow> = self.flows.values().collect();
        match sort {
            FlowSort::Bytes   => v.sort_by(|a, b| b.bytes.cmp(&a.bytes)),
            FlowSort::Packets => v.sort_by(|a, b| b.packets.cmp(&a.packets)),
            FlowSort::Time    => v.sort_by(|a, b| b.first_seen.partial_cmp(&a.first_seen).unwrap_or(std::cmp::Ordering::Equal)),
        }
        v
    }

    pub fn clear(&mut self) {
        self.flows.clear();
        self.scan_seen.clear();
    }
}
