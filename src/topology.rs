use std::collections::HashMap;
use crate::net::packet::Packet;

/// Tracks observed nodes and directed flows between them.
#[derive(Default)]
pub struct TopologyGraph {
    pub nodes: HashMap<String, NodeInfo>,
    pub edges: HashMap<(String, String), EdgeInfo>,
}

#[derive(Default, Clone)]
pub struct NodeInfo {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

#[derive(Default, Clone)]
pub struct EdgeInfo {
    pub packets: u64,
    pub bytes: u64,
    pub protocol: String,
}

impl TopologyGraph {
    pub fn update(&mut self, pkt: &Packet) {
        let src = self.nodes.entry(pkt.src.clone()).or_default();
        src.tx_packets += 1;
        src.tx_bytes += pkt.length as u64;

        let dst = self.nodes.entry(pkt.dst.clone()).or_default();
        dst.rx_packets += 1;
        dst.rx_bytes += pkt.length as u64;

        let edge = self.edges
            .entry((pkt.src.clone(), pkt.dst.clone()))
            .or_default();
        edge.packets += 1;
        edge.bytes += pkt.length as u64;
        edge.protocol = pkt.protocol.clone();
    }

    pub fn clear(&mut self) {
        self.nodes.clear();
        self.edges.clear();
    }

    /// Top nodes by total traffic (tx+rx packets), descending.
    pub fn top_nodes(&self, n: usize) -> Vec<(&str, &NodeInfo)> {
        let mut v: Vec<_> = self.nodes.iter()
            .map(|(ip, info)| (ip.as_str(), info))
            .collect();
        v.sort_by(|a, b| {
            let ta = a.1.tx_packets + a.1.rx_packets;
            let tb = b.1.tx_packets + b.1.rx_packets;
            tb.cmp(&ta)
        });
        v.truncate(n);
        v
    }

    /// Top edges by packet count, descending.
    pub fn top_edges(&self, n: usize) -> Vec<(&str, &str, &EdgeInfo)> {
        let mut v: Vec<_> = self.edges.iter()
            .map(|((src, dst), info)| (src.as_str(), dst.as_str(), info))
            .collect();
        v.sort_by(|a, b| b.2.packets.cmp(&a.2.packets));
        v.truncate(n);
        v
    }
}
