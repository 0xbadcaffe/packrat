//! Core graph data structures: nodes, edges, filters, and snapshots.

use std::collections::HashSet;
use crate::model::graph_types::{GraphNodeKind, GraphEdgeKind, GraphNodeData};
use crate::model::graph_evidence::GraphEvidenceRef;

pub type GraphNodeId = u64;
pub type GraphEdgeId = u64;
pub type Timestamp   = f64;

// ─── Graph node ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GraphNode {
    pub id:         GraphNodeId,
    /// Normalized deduplication key: `"{kind}:{canonical_value}"`.
    pub key:        String,
    pub label:      String,
    pub first_seen: Timestamp,
    pub last_seen:  Timestamp,
    pub hit_count:  u64,
    /// Composite risk/confidence score in [0, 1].
    pub score:      f32,
    pub tags:       HashSet<String>,
    /// Evidence links backing this node.
    pub evidence:   Vec<GraphEvidenceRef>,
    /// Typed payload.
    pub data:       GraphNodeData,
    /// Human-readable score explanation.
    pub score_why:  String,
}

impl GraphNode {
    pub fn new(key: impl Into<String>, label: impl Into<String>, ts: Timestamp, data: GraphNodeData) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self {
            id:         NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            key:        key.into(),
            label:      label.into(),
            first_seen: ts,
            last_seen:  ts,
            hit_count:  1,
            score:      0.0,
            tags:       HashSet::new(),
            evidence:   Vec::new(),
            data,
            score_why:  String::new(),
        }
    }

    pub fn kind(&self) -> GraphNodeKind { self.data.kind() }

    pub fn touch(&mut self, ts: Timestamp) {
        if ts > self.last_seen { self.last_seen = ts; }
        if ts < self.first_seen { self.first_seen = ts; }
        self.hit_count += 1;
    }

    pub fn add_evidence(&mut self, ev: GraphEvidenceRef) {
        if !self.evidence.contains(&ev) { self.evidence.push(ev); }
    }

    pub fn add_tag(&mut self, tag: impl Into<String>) { self.tags.insert(tag.into()); }

    pub fn risk_label(&self) -> &'static str {
        if self.score >= 0.85 { "CRITICAL" }
        else if self.score >= 0.65 { "HIGH" }
        else if self.score >= 0.40 { "MEDIUM" }
        else if self.score >= 0.15 { "LOW" }
        else { "INFO" }
    }

    pub fn stars(&self) -> &'static str {
        if self.score >= 0.85 { "★★★★★" }
        else if self.score >= 0.65 { "★★★★☆" }
        else if self.score >= 0.40 { "★★★☆☆" }
        else if self.score >= 0.15 { "★★☆☆☆" }
        else { "★☆☆☆☆" }
    }
}

// ─── Graph edge ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GraphEdge {
    pub id:         GraphEdgeId,
    pub src:        GraphNodeId,
    pub dst:        GraphNodeId,
    pub kind:       GraphEdgeKind,
    pub confidence: f32,
    pub first_seen: Timestamp,
    pub last_seen:  Timestamp,
    pub hit_count:  u64,
    pub evidence:   Vec<GraphEvidenceRef>,
    pub meta:       EdgeMeta,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EdgeMeta {
    pub port:      Option<u16>,
    pub protocol:  Option<String>,
    pub pkt_count: u64,
    pub byte_count: u64,
    pub score:     f32,
}

impl GraphEdge {
    pub fn new(src: GraphNodeId, dst: GraphNodeId, kind: GraphEdgeKind, ts: Timestamp, confidence: f32) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self {
            id:         NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            src,
            dst,
            kind,
            confidence,
            first_seen: ts,
            last_seen:  ts,
            hit_count:  1,
            evidence:   Vec::new(),
            meta:       EdgeMeta::default(),
        }
    }

    pub fn touch(&mut self, ts: Timestamp, bytes: u64) {
        if ts > self.last_seen { self.last_seen = ts; }
        self.hit_count += 1;
        self.meta.pkt_count += 1;
        self.meta.byte_count += bytes;
    }

    pub fn add_evidence(&mut self, ev: GraphEvidenceRef) {
        if !self.evidence.contains(&ev) { self.evidence.push(ev); }
    }
}

// ─── View filter ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct GraphViewFilter {
    pub node_kinds:   Vec<GraphNodeKind>,
    pub edge_kinds:   Vec<GraphEdgeKind>,
    pub min_score:    f32,
    pub time_start:   Option<Timestamp>,
    pub time_end:     Option<Timestamp>,
    pub tags:         Vec<String>,
    pub marked_only:  bool,
    pub search:       String,
}

impl GraphViewFilter {
    pub fn node_passes(&self, node: &GraphNode) -> bool {
        if !self.node_kinds.is_empty() && !self.node_kinds.contains(&node.kind()) { return false; }
        if node.score < self.min_score { return false; }
        if let Some(start) = self.time_start { if node.last_seen < start { return false; } }
        if let Some(end)   = self.time_end   { if node.first_seen > end  { return false; } }
        if !self.tags.is_empty() && !self.tags.iter().any(|t| node.tags.contains(t)) { return false; }
        if !self.search.is_empty() {
            let q = self.search.to_lowercase();
            if !node.label.to_lowercase().contains(&q) { return false; }
        }
        true
    }
}

// ─── Graph snapshot ───────────────────────────────────────────────────────────

/// Filtered subgraph for display.
#[derive(Debug, Default)]
pub struct GraphSnapshot {
    pub node_ids: Vec<GraphNodeId>,
    pub edge_ids: Vec<GraphEdgeId>,
}
