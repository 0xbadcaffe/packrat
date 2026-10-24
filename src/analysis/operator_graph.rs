//! Operator Graph engine — builds a live correlation graph from all analysis subsystems.
//!
//! The engine receives incremental updates and maintains typed nodes/edges with
//! provenance, timestamps, and risk scores. All heavy analysis (paths, clusters,
//! scoring) can be triggered lazily rather than on every packet.

use crate::analysis::graph_cluster::{GraphCluster, compute_clusters};
use crate::analysis::graph_scoring::score_nodes;
use crate::analysis::path_reconstruction::{AttackPath, reconstruct_paths};
use crate::analysis::pivot::{PivotSuggestion, pivot_suggestions_for};
use crate::model::evidence::PacketRef;
use crate::model::graph::{
    GraphEdge, GraphEdgeId, GraphNode, GraphNodeId, GraphSnapshot, GraphViewFilter, Timestamp,
};
use crate::model::graph_evidence::GraphEvidenceRef;
use crate::model::graph_types::*;
use std::collections::HashMap;

// ─── UI state ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum GraphUiMode {
    Neighborhood,
    Adjacency,
    Paths,
    Clusters,
    Evidence,
}

impl std::fmt::Display for GraphUiMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Neighborhood => write!(f, "Neighborhood"),
            Self::Adjacency => write!(f, "Adjacency"),
            Self::Paths => write!(f, "Paths"),
            Self::Clusters => write!(f, "Clusters"),
            Self::Evidence => write!(f, "Evidence"),
        }
    }
}

#[derive(Debug, Default)]
pub struct GraphUiState {
    pub selected_node: Option<GraphNodeId>,
    pub list_scroll: usize,
    pub neighbor_scroll: usize,
    pub detail_scroll: usize,
    pub mode: GraphUiModeState,
    pub pivot_history: Vec<GraphNodeId>,
    pub filter: GraphViewFilter,
    pub search: String,
    pub searching: bool,
    pub path_selected: usize,
    pub cluster_selected: usize,
    pub evidence_scroll: usize,
    // High-water marks for incremental sync from other engines
    pub synced_alerts: usize,
    pub synced_ioc_hits: usize,
    pub synced_creds: usize,
    pub synced_objects: usize,
    pub synced_tls: usize,
    pub synced_rule_hits: usize,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub enum GraphUiModeState {
    #[default]
    Neighborhood,
    Adjacency,
    Paths,
    Clusters,
    Evidence,
}

impl GraphUiModeState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Neighborhood => "Neighborhood",
            Self::Adjacency => "Adjacency",
            Self::Paths => "Paths",
            Self::Clusters => "Clusters",
            Self::Evidence => "Evidence",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            Self::Neighborhood => Self::Adjacency,
            Self::Adjacency => Self::Paths,
            Self::Paths => Self::Clusters,
            Self::Clusters => Self::Evidence,
            Self::Evidence => Self::Neighborhood,
        }
    }
}

// ─── Graph engine ─────────────────────────────────────────────────────────────

pub struct OperatorGraphEngine {
    /// All nodes by ID.
    nodes: HashMap<GraphNodeId, GraphNode>,
    /// All edges by ID.
    edges: HashMap<GraphEdgeId, GraphEdge>,
    /// Normalized key → node ID (for deduplication).
    key_index: HashMap<String, GraphNodeId>,
    /// Outgoing edges per node.
    out_edges: HashMap<GraphNodeId, Vec<GraphEdgeId>>,
    /// Incoming edges per node.
    in_edges: HashMap<GraphNodeId, Vec<GraphEdgeId>>,
    /// (src, dst, kind_str) → edge ID (prevents duplicate edges).
    edge_index: HashMap<(GraphNodeId, GraphNodeId, String), GraphEdgeId>,
    /// Cached attack paths (rebuilt lazily).
    pub paths: Vec<AttackPath>,
    /// Cached clusters (rebuilt lazily).
    pub clusters: Vec<GraphCluster>,
    /// Cached pivot suggestions for the last queried node.
    pub pivots: Vec<PivotSuggestion>,
    pub pivots_for: Option<GraphNodeId>,
    /// Stats
    pub total_events: u64,
}

impl Default for OperatorGraphEngine {
    fn default() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            key_index: HashMap::new(),
            out_edges: HashMap::new(),
            in_edges: HashMap::new(),
            edge_index: HashMap::new(),
            paths: Vec::new(),
            clusters: Vec::new(),
            pivots: Vec::new(),
            pivots_for: None,
            total_events: 0,
        }
    }
}

impl OperatorGraphEngine {
    // ─── Core node/edge management ────────────────────────────────────────────

    /// Insert or update a node by its normalized key. Returns the node ID.
    pub fn ensure_node(
        &mut self,
        key: String,
        label: String,
        ts: Timestamp,
        data: GraphNodeData,
    ) -> GraphNodeId {
        if let Some(&id) = self.key_index.get(&key) {
            let node = self.nodes.get_mut(&id).unwrap();
            node.touch(ts);
            return id;
        }
        let node = GraphNode::new(key.clone(), label, ts, data);
        let id = node.id;
        self.key_index.insert(key, id);
        self.out_edges.entry(id).or_default();
        self.in_edges.entry(id).or_default();
        self.nodes.insert(id, node);
        id
    }

    /// Insert or update an edge. Returns the edge ID.
    pub fn ensure_edge(
        &mut self,
        src: GraphNodeId,
        dst: GraphNodeId,
        kind: GraphEdgeKind,
        ts: Timestamp,
        confidence: f32,
        bytes: u64,
    ) -> GraphEdgeId {
        let kind_str = kind.to_string();
        let ekey = (src, dst, kind_str);
        if let Some(&eid) = self.edge_index.get(&ekey) {
            let edge = self.edges.get_mut(&eid).unwrap();
            edge.touch(ts, bytes);
            return eid;
        }
        let edge = GraphEdge::new(src, dst, kind.clone(), ts, confidence);
        let eid = edge.id;
        self.edge_index.insert(ekey, eid);
        self.out_edges.entry(src).or_default().push(eid);
        self.in_edges.entry(dst).or_default().push(eid);
        self.edges.insert(eid, edge);
        eid
    }

    pub fn add_node_evidence(&mut self, id: GraphNodeId, ev: GraphEvidenceRef) {
        if let Some(n) = self.nodes.get_mut(&id) {
            n.add_evidence(ev);
        }
    }

    pub fn add_edge_evidence(&mut self, id: GraphEdgeId, ev: GraphEvidenceRef) {
        if let Some(e) = self.edges.get_mut(&id) {
            e.add_evidence(ev);
        }
    }

    pub fn tag_node(&mut self, id: GraphNodeId, tag: impl Into<String>) {
        if let Some(n) = self.nodes.get_mut(&id) {
            n.add_tag(tag);
        }
    }

    // ─── Public queries ───────────────────────────────────────────────────────

    pub fn get_node(&self, id: GraphNodeId) -> Option<&GraphNode> {
        self.nodes.get(&id)
    }
    pub fn get_edge(&self, id: GraphEdgeId) -> Option<&GraphEdge> {
        self.edges.get(&id)
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Outgoing edge IDs from a node.
    pub fn out_edges(&self, id: GraphNodeId) -> &[GraphEdgeId] {
        self.out_edges.get(&id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Incoming edge IDs to a node.
    pub fn in_edges(&self, id: GraphNodeId) -> &[GraphEdgeId] {
        self.in_edges.get(&id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// All edge IDs connected to a node (in + out).
    pub fn neighbors(&self, id: GraphNodeId) -> Vec<GraphEdgeId> {
        let mut v = Vec::new();
        if let Some(out) = self.out_edges.get(&id) {
            v.extend_from_slice(out);
        }
        if let Some(inc) = self.in_edges.get(&id) {
            v.extend_from_slice(inc);
        }
        v.dedup();
        v
    }

    pub fn nodes_by_kind(&self, kind: &GraphNodeKind) -> Vec<GraphNodeId> {
        self.nodes
            .values()
            .filter(|n| &n.kind() == kind)
            .map(|n| n.id)
            .collect()
    }

    /// All nodes sorted by score descending.
    pub fn all_nodes_sorted(&self) -> Vec<&GraphNode> {
        let mut v: Vec<_> = self.nodes.values().collect();
        v.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        v
    }

    /// Filtered snapshot respecting GraphViewFilter.
    pub fn filtered_snapshot(&self, filter: &GraphViewFilter) -> GraphSnapshot {
        let node_ids: Vec<_> = self
            .nodes
            .values()
            .filter(|n| filter.node_passes(n))
            .map(|n| n.id)
            .collect();
        let node_set: std::collections::HashSet<_> = node_ids.iter().copied().collect();
        let edge_ids: Vec<_> = self
            .edges
            .values()
            .filter(|e| node_set.contains(&e.src) && node_set.contains(&e.dst))
            .map(|e| e.id)
            .collect();
        GraphSnapshot { node_ids, edge_ids }
    }

    // ─── Packet-level ingestion ───────────────────────────────────────────────

    /// Recompute risk scores for all nodes (call from tick, not per-packet).
    pub fn recompute_scores(&mut self) {
        let updates = score_nodes(&self.nodes, &self.edges, &self.out_edges, &self.in_edges);
        for (id, score, why) in updates {
            if let Some(n) = self.nodes.get_mut(&id) {
                n.score = score;
                n.score_why = why;
            }
        }
    }

    /// Rebuild attack path candidates (call periodically, not per-packet).
    pub fn recompute_paths(&mut self) {
        self.paths = reconstruct_paths(&self.nodes, &self.edges, &self.out_edges);
    }

    /// Rebuild clusters (call periodically).
    pub fn recompute_clusters(&mut self) {
        self.clusters = compute_clusters(&self.nodes, &self.edges, &self.out_edges, &self.in_edges);
    }

    /// Refresh pivot suggestions for the given node.
    pub fn recompute_pivots(&mut self, node_id: GraphNodeId) {
        self.pivots = pivot_suggestions_for(
            node_id,
            &self.nodes,
            &self.edges,
            &self.out_edges,
            &self.in_edges,
        );
        self.pivots_for = Some(node_id);
    }

    // ─── Persistence helpers ──────────────────────────────────────────────────

    pub fn all_nodes(&self) -> impl Iterator<Item = &GraphNode> {
        self.nodes.values()
    }
    pub fn all_edges(&self) -> impl Iterator<Item = &GraphEdge> {
        self.edges.values()
    }

    pub fn clear(&mut self) {
        self.nodes.clear();
        self.edges.clear();
        self.key_index.clear();
        self.out_edges.clear();
        self.in_edges.clear();
        self.edge_index.clear();
        self.paths.clear();
        self.clusters.clear();
        self.pivots.clear();
        self.pivots_for = None;
        self.total_events = 0;
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn known_service_role(port: u16, proto: &str) -> Option<String> {
    if proto != "TCP" && proto != "UDP" {
        return None;
    }
    let role = match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        6379 => "Redis",
        8080 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        _ => return None,
    };
    Some(role.to_string())
}

fn human_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1_048_576 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}MB", bytes as f64 / 1_048_576.0)
    }
}

mod events;
