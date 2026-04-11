//! Pivot engine — given a selected graph node, suggest the most useful next pivots.

use std::collections::HashMap;
use crate::model::graph::{GraphNode, GraphEdge, GraphEdgeId, GraphNodeId};
use crate::model::graph_types::GraphNodeKind;
use crate::model::graph_evidence::GraphEvidenceRef;

// ─── Pivot target ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum PivotTarget {
    Node(GraphNodeId),
    Kind(GraphNodeKind),
    Evidence(GraphEvidenceRef),
    FilteredList { kind: GraphNodeKind, query: String },
}

// ─── Pivot suggestion ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PivotSuggestion {
    pub label:  String,
    pub target: PivotTarget,
    pub reason: String,
    pub score:  f32,
}

// ─── Pivot computation ────────────────────────────────────────────────────────

pub fn pivot_suggestions_for(
    node_id:   GraphNodeId,
    nodes:     &HashMap<GraphNodeId, GraphNode>,
    edges:     &HashMap<GraphEdgeId, GraphEdge>,
    out_edges: &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
    in_edges:  &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
) -> Vec<PivotSuggestion> {
    let Some(node) = nodes.get(&node_id) else { return Vec::new(); };
    let mut suggestions = Vec::new();

    // Gather neighbor nodes with their edge kinds
    let all_edge_ids: Vec<GraphEdgeId> = {
        let mut v = Vec::new();
        if let Some(out) = out_edges.get(&node_id) { v.extend_from_slice(out); }
        if let Some(inc) = in_edges.get(&node_id)  { v.extend_from_slice(inc); }
        v.dedup();
        v
    };

    for eid in &all_edge_ids {
        let Some(edge) = edges.get(eid) else { continue };
        let neighbor_id = if edge.src == node_id { edge.dst } else { edge.src };
        let Some(neighbor) = nodes.get(&neighbor_id) else { continue };

        let label = format!("{} → {} ({})", edge.kind, neighbor.label, neighbor.kind());
        let score = neighbor.score.max(edge.confidence * 0.5);
        suggestions.push(PivotSuggestion {
            label:  label.clone(),
            target: PivotTarget::Node(neighbor_id),
            reason: format!("connected via {}", edge.kind),
            score,
        });
    }

    // Kind-specific high-value pivots
    match node.data.kind() {
        GraphNodeKind::Host => {
            // Suggest cert reuse check
            suggestions.push(PivotSuggestion {
                label:  "Check certificate reuse".into(),
                target: PivotTarget::Kind(GraphNodeKind::Certificate),
                reason: "Hosts sharing certs may belong to same infrastructure".into(),
                score:  0.6,
            });
            // Suggest credential exposure check
            if node.score > 0.3 {
                suggestions.push(PivotSuggestion {
                    label:  "View exposed credentials".into(),
                    target: PivotTarget::FilteredList { kind: GraphNodeKind::Credential, query: node.label.clone() },
                    reason: "Host has elevated risk score".into(),
                    score:  0.75,
                });
            }
        }
        GraphNodeKind::Certificate => {
            suggestions.push(PivotSuggestion {
                label:  "Find all hosts using this cert".into(),
                target: PivotTarget::FilteredList { kind: GraphNodeKind::Host, query: node.label.clone() },
                reason: "Certificate reuse across hosts is suspicious".into(),
                score:  0.8,
            });
        }
        GraphNodeKind::Credential => {
            suggestions.push(PivotSuggestion {
                label:  "Check for credential reuse".into(),
                target: PivotTarget::Kind(GraphNodeKind::Credential),
                reason: "Same credential used on multiple services".into(),
                score:  0.9,
            });
        }
        GraphNodeKind::IOC => {
            suggestions.push(PivotSuggestion {
                label:  "Find all matching hosts".into(),
                target: PivotTarget::Kind(GraphNodeKind::Host),
                reason: "All hosts that contacted this IOC".into(),
                score:  0.85,
            });
        }
        GraphNodeKind::Flow => {
            suggestions.push(PivotSuggestion {
                label:  "Follow stream".into(),
                target: PivotTarget::Kind(GraphNodeKind::Stream),
                reason: "Reassembled TCP stream from this flow".into(),
                score:  0.7,
            });
            suggestions.push(PivotSuggestion {
                label:  "Check for extracted files".into(),
                target: PivotTarget::Kind(GraphNodeKind::FileObject),
                reason: "Files carved from this flow".into(),
                score:  0.65,
            });
        }
        GraphNodeKind::FileObject => {
            suggestions.push(PivotSuggestion {
                label:  "Source stream".into(),
                target: PivotTarget::Kind(GraphNodeKind::Stream),
                reason: "Stream this file was carved from".into(),
                score:  0.8,
            });
            suggestions.push(PivotSuggestion {
                label:  "YARA hits".into(),
                target: PivotTarget::Evidence(GraphEvidenceRef::YaraHit(node_id)),
                reason: "YARA rule matches on this object".into(),
                score:  0.9,
            });
        }
        _ => {}
    }

    // Sort by score descending
    suggestions.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    suggestions.truncate(8);
    suggestions
}
