//! Risk scoring for graph nodes.
//!
//! Scores are in [0, 1]. Every score comes with a human-readable explanation.
//! Scoring is explainable by design — no black-box aggregation.

use std::collections::HashMap;
use crate::model::graph::{GraphNode, GraphEdge, GraphEdgeId, GraphNodeId};
use crate::model::graph_types::{GraphEdgeKind, GraphNodeKind};

/// Returns (node_id, new_score, explanation) for each node.
pub fn score_nodes(
    nodes:     &HashMap<GraphNodeId, GraphNode>,
    edges:     &HashMap<GraphEdgeId, GraphEdge>,
    out_edges: &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
    in_edges:  &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
) -> Vec<(GraphNodeId, f32, String)> {
    let mut results = Vec::new();

    for (id, node) in nodes.iter() {
        let (score, why) = match node.data.kind() {
            GraphNodeKind::Host       => score_host(*id, node, edges, out_edges, in_edges, nodes),
            GraphNodeKind::Credential => score_credential(*id, node, edges, in_edges, nodes),
            GraphNodeKind::Certificate => score_certificate(*id, node, edges, in_edges),
            GraphNodeKind::IOC        => score_ioc(*id, node, edges, in_edges),
            GraphNodeKind::Alert      => score_alert(node),
            GraphNodeKind::FileObject => score_file_object(node),
            GraphNodeKind::Flow       => score_flow(*id, node, edges, out_edges),
            _                         => (node.score, node.score_why.clone()),
        };
        results.push((*id, score, why));
    }
    results
}

// ─── Host scoring ─────────────────────────────────────────────────────────────

fn score_host(
    id:        GraphNodeId,
    _node:     &GraphNode,
    edges:     &HashMap<GraphEdgeId, GraphEdge>,
    out_edges: &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
    in_edges:  &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
    nodes:     &HashMap<GraphNodeId, GraphNode>,
) -> (f32, String) {
    let mut score: f32 = 0.0;
    let mut reasons: Vec<String> = Vec::new();

    let eids: Vec<GraphEdgeId> = {
        let mut v = Vec::new();
        if let Some(o) = out_edges.get(&id) { v.extend_from_slice(o); }
        if let Some(i) = in_edges.get(&id)  { v.extend_from_slice(i); }
        v
    };

    let mut alert_count  = 0u32;
    let mut ioc_count    = 0u32;
    let mut cred_count   = 0u32;
    let mut high_sev     = false;

    for eid in &eids {
        let Some(edge) = edges.get(eid) else { continue };
        let neighbor_id = if edge.src == id { edge.dst } else { edge.src };
        let Some(neighbor) = nodes.get(&neighbor_id) else { continue };

        match edge.kind {
            GraphEdgeKind::TriggersAlert => {
                alert_count += 1;
                if neighbor.score_why.contains("HIGH") || neighbor.score_why.contains("CRITICAL") {
                    high_sev = true;
                }
            }
            GraphEdgeKind::MatchesIoc => { ioc_count += 1; }
            GraphEdgeKind::AuthenticatedWith => { cred_count += 1; }
            _ => {}
        }
    }

    if ioc_count > 0 {
        score += 0.35 * (ioc_count as f32).min(3.0) / 3.0;
        reasons.push(format!("{ioc_count} IOC hit(s)"));
    }
    if alert_count > 0 {
        score += 0.25 * (alert_count as f32).min(5.0) / 5.0;
        reasons.push(format!("{alert_count} alert(s)"));
    }
    if high_sev { score += 0.15; reasons.push("high-sev alert".into()); }
    if cred_count > 0 {
        score += 0.15 * (cred_count as f32).min(3.0) / 3.0;
        reasons.push(format!("{cred_count} credential(s) seen"));
    }

    // Beacon-like behavior: many outgoing communications to same host
    let repeat_comms: u64 = eids.iter()
        .filter_map(|eid| edges.get(eid))
        .filter(|e| e.src == id && e.kind == GraphEdgeKind::CommunicatesWith && e.hit_count > 30)
        .map(|e| e.hit_count)
        .sum();
    if repeat_comms > 100 {
        score += 0.10;
        reasons.push("beacon-like repetition".into());
    }

    score = score.min(1.0);
    let why = if reasons.is_empty() {
        format!("Host risk {score:.2}: no significant signals")
    } else {
        format!("Host risk {score:.2}: {}", reasons.join(", "))
    };
    (score, why)
}

// ─── Credential scoring ───────────────────────────────────────────────────────

fn score_credential(
    id:       GraphNodeId,
    node:     &GraphNode,
    edges:    &HashMap<GraphEdgeId, GraphEdge>,
    in_edges: &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
    nodes:    &HashMap<GraphNodeId, GraphNode>,
) -> (f32, String) {
    let mut score: f32 = 0.0;
    let mut reasons: Vec<String> = Vec::new();

    // Cleartext?
    if let crate::model::graph_types::GraphNodeData::Credential(ref d) = node.data {
        if d.cleartext { score += 0.4; reasons.push("cleartext".into()); }
    }

    // How many distinct sources?
    let src_count = in_edges.get(&id)
        .map(|eids| eids.iter()
            .filter_map(|eid| edges.get(eid))
            .filter(|e| e.kind == GraphEdgeKind::AuthenticatedWith)
            .count())
        .unwrap_or(0);
    if src_count > 1 {
        score += 0.3 * (src_count as f32 / 5.0).min(1.0);
        reasons.push(format!("seen from {src_count} sources"));
    }

    score = score.min(1.0);
    let _ = (nodes, id);
    (score, format!("Credential risk {score:.2}: {}", if reasons.is_empty() { "normal".into() } else { reasons.join(", ") }))
}

// ─── Certificate scoring ──────────────────────────────────────────────────────

fn score_certificate(
    id:       GraphNodeId,
    node:     &GraphNode,
    edges:    &HashMap<GraphEdgeId, GraphEdge>,
    in_edges: &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
) -> (f32, String) {
    let mut score: f32 = 0.0;
    let mut reasons: Vec<String> = Vec::new();

    if let crate::model::graph_types::GraphNodeData::Certificate(ref d) = node.data {
        if d.self_signed { score += 0.25; reasons.push("self-signed".into()); }
    }

    // Reuse across flows
    let reuse_count = in_edges.get(&id)
        .map(|eids| eids.iter()
            .filter_map(|eid| edges.get(eid))
            .filter(|e| e.kind == GraphEdgeKind::PresentsCertificate)
            .count())
        .unwrap_or(0);
    if reuse_count > 1 {
        score += 0.20 * (reuse_count as f32 / 5.0).min(1.0);
        reasons.push(format!("reused in {reuse_count} flows"));
    }

    let _ = (id, node);
    score = score.min(1.0);
    (score, format!("Cert risk {score:.2}: {}", if reasons.is_empty() { "ok".into() } else { reasons.join(", ") }))
}

// ─── IOC scoring ──────────────────────────────────────────────────────────────

fn score_ioc(
    id:       GraphNodeId,
    _node:    &GraphNode,
    edges:    &HashMap<GraphEdgeId, GraphEdge>,
    in_edges: &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
) -> (f32, String) {
    let hit_count = in_edges.get(&id)
        .map(|eids| eids.iter()
            .filter_map(|eid| edges.get(eid))
            .filter(|e| e.kind == GraphEdgeKind::MatchesIoc)
            .count())
        .unwrap_or(0);
    let score = (0.5 + hit_count as f32 * 0.1).min(0.95);
    (score, format!("IOC risk {score:.2}: {hit_count} host match(es)"))
}

// ─── Alert scoring ────────────────────────────────────────────────────────────

fn score_alert(node: &GraphNode) -> (f32, String) {
    let score = if let crate::model::graph_types::GraphNodeData::Alert(ref d) = node.data {
        match d.severity.to_uppercase().as_str() {
            "CRITICAL" => 0.95,
            "HIGH"     => 0.80,
            "MEDIUM"   => 0.55,
            "LOW"      => 0.30,
            _          => 0.15,
        }
    } else { 0.1 };
    (score, format!("Alert risk {score:.2}"))
}

// ─── File object scoring ──────────────────────────────────────────────────────

fn score_file_object(node: &GraphNode) -> (f32, String) {
    let mut score: f32 = 0.10;
    let mut reasons: Vec<String> = Vec::new();

    if let crate::model::graph_types::GraphNodeData::FileObject(ref d) = node.data {
        if !d.yara_hits.is_empty() {
            score += 0.4;
            reasons.push(format!("{} YARA hit(s)", d.yara_hits.len()));
        }
        let suspicious_mime = ["application/exe", "application/elf", "application/x-msdownload"];
        if suspicious_mime.iter().any(|m| d.mime.contains(m)) {
            score += 0.25;
            reasons.push("executable MIME".into());
        }
    }

    score = score.min(1.0);
    (score, format!("File risk {score:.2}: {}", if reasons.is_empty() { "benign".into() } else { reasons.join(", ") }))
}

// ─── Flow scoring ─────────────────────────────────────────────────────────────

fn score_flow(
    id:        GraphNodeId,
    _node:     &GraphNode,
    edges:     &HashMap<GraphEdgeId, GraphEdge>,
    out_edges: &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
) -> (f32, String) {
    // A flow with many extracted objects or certs is more interesting
    let out: Vec<_> = out_edges.get(&id)
        .map(|eids| eids.iter().filter_map(|eid| edges.get(eid)).collect())
        .unwrap_or_default();

    let has_cert  = out.iter().any(|e| e.kind == GraphEdgeKind::PresentsCertificate);
    let has_file  = out.iter().any(|e| e.kind == GraphEdgeKind::ExtractedFrom);
    let score = 0.05 + if has_cert { 0.15 } else { 0.0 } + if has_file { 0.20 } else { 0.0 };
    (score, format!("Flow risk {score:.2}"))
}
