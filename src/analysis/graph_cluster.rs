//! Graph clustering — groups suspiciously related nodes into named clusters.

use std::collections::HashMap;
use crate::model::graph::{GraphNode, GraphEdge, GraphEdgeId, GraphNodeId};
use crate::model::graph_types::{GraphEdgeKind, GraphNodeKind};

// ─── Cluster ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GraphCluster {
    pub id:      u64,
    pub label:   String,
    pub kind:    ClusterKind,
    pub members: Vec<GraphNodeId>,
    pub score:   f32,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClusterKind {
    CertReuse,
    CredReuse,
    IocGroup,
    BeaconGroup,
    AlertedHosts,
    SuspiciousInfra,
}

impl std::fmt::Display for ClusterKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::CertReuse      => "Cert Reuse",
            Self::CredReuse      => "Credential Reuse",
            Self::IocGroup       => "IOC Group",
            Self::BeaconGroup    => "Beacon Group",
            Self::AlertedHosts   => "Alerted Hosts",
            Self::SuspiciousInfra => "Suspicious Infrastructure",
        };
        write!(f, "{s}")
    }
}

static CLUSTER_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
fn next_cluster_id() -> u64 { CLUSTER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed) }

// ─── Compute clusters ─────────────────────────────────────────────────────────

pub fn compute_clusters(
    nodes:     &HashMap<GraphNodeId, GraphNode>,
    edges:     &HashMap<GraphEdgeId, GraphEdge>,
    out_edges: &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
    in_edges:  &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
) -> Vec<GraphCluster> {
    let mut clusters = Vec::new();

    clusters.extend(cert_reuse_clusters(nodes, edges, in_edges));
    clusters.extend(ioc_clusters(nodes, edges, in_edges));
    clusters.extend(alerted_host_cluster(nodes, edges, out_edges));
    clusters.extend(beacon_clusters(nodes, edges, out_edges));

    clusters.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    clusters.truncate(20);
    clusters
}

// ─── Certificate reuse clusters ───────────────────────────────────────────────

fn cert_reuse_clusters(
    nodes:    &HashMap<GraphNodeId, GraphNode>,
    edges:    &HashMap<GraphEdgeId, GraphEdge>,
    in_edges: &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
) -> Vec<GraphCluster> {
    let mut clusters = Vec::new();
    for (_, cert) in nodes.iter().filter(|(_, n)| n.data.kind() == GraphNodeKind::Certificate) {
        let users: Vec<GraphNodeId> = in_edges.get(&cert.id)
            .map(|eids| eids.iter()
                .filter_map(|eid| edges.get(eid))
                .filter(|e| e.kind == GraphEdgeKind::PresentsCertificate)
                .map(|e| e.src)
                .collect())
            .unwrap_or_default();
        if users.len() >= 2 {
            let score = (0.4 + users.len() as f32 * 0.1).min(0.9);
            let mut members = vec![cert.id];
            members.extend_from_slice(&users);
            clusters.push(GraphCluster {
                id:      next_cluster_id(),
                label:   format!("Cert: {}", cert.label),
                kind:    ClusterKind::CertReuse,
                members,
                score,
                summary: format!("Certificate '{}' seen in {} connections — possible shared infra", cert.label, users.len()),
            });
        }
    }
    clusters
}

// ─── IOC groups ───────────────────────────────────────────────────────────────

fn ioc_clusters(
    nodes:    &HashMap<GraphNodeId, GraphNode>,
    edges:    &HashMap<GraphEdgeId, GraphEdge>,
    in_edges: &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
) -> Vec<GraphCluster> {
    let mut clusters = Vec::new();
    for (_, ioc) in nodes.iter().filter(|(_, n)| n.data.kind() == GraphNodeKind::IOC) {
        let matching: Vec<GraphNodeId> = in_edges.get(&ioc.id)
            .map(|eids| eids.iter()
                .filter_map(|eid| edges.get(eid))
                .filter(|e| e.kind == GraphEdgeKind::MatchesIoc)
                .map(|e| e.src)
                .collect())
            .unwrap_or_default();
        if !matching.is_empty() {
            let score = (0.55 + matching.len() as f32 * 0.1).min(0.95);
            let mut members = vec![ioc.id];
            members.extend_from_slice(&matching);
            clusters.push(GraphCluster {
                id:      next_cluster_id(),
                label:   format!("IOC: {}", ioc.label),
                kind:    ClusterKind::IocGroup,
                members,
                score,
                summary: format!("{} host(s) matched IOC '{}'", matching.len(), ioc.label),
            });
        }
    }
    clusters
}

// ─── Alerted hosts ────────────────────────────────────────────────────────────

fn alerted_host_cluster(
    nodes:     &HashMap<GraphNodeId, GraphNode>,
    edges:     &HashMap<GraphEdgeId, GraphEdge>,
    out_edges: &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
) -> Vec<GraphCluster> {
    let alerted: Vec<GraphNodeId> = nodes.iter()
        .filter(|(_, n)| n.data.kind() == GraphNodeKind::Host)
        .filter(|(id, _)| {
            out_edges.get(id)
                .map(|eids| eids.iter()
                    .filter_map(|eid| edges.get(eid))
                    .any(|e| e.kind == GraphEdgeKind::TriggersAlert))
                .unwrap_or(false)
        })
        .map(|(id, _)| *id)
        .collect();

    if alerted.len() >= 2 {
        vec![GraphCluster {
            id:      next_cluster_id(),
            label:   "Alerted Hosts".into(),
            kind:    ClusterKind::AlertedHosts,
            members: alerted.clone(),
            score:   0.70,
            summary: format!("{} host(s) with IDS alerts", alerted.len()),
        }]
    } else {
        vec![]
    }
}

// ─── Beacon group ─────────────────────────────────────────────────────────────

fn beacon_clusters(
    nodes:     &HashMap<GraphNodeId, GraphNode>,
    edges:     &HashMap<GraphEdgeId, GraphEdge>,
    out_edges: &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
) -> Vec<GraphCluster> {
    let mut beacon_pairs: Vec<(GraphNodeId, GraphNodeId, f32)> = Vec::new();

    for (src_id, eids) in out_edges.iter() {
        for eid in eids {
            if let Some(e) = edges.get(eid) {
                if e.kind == GraphEdgeKind::CommunicatesWith && e.hit_count >= 20 {
                    let duration = e.last_seen - e.first_seen;
                    if duration >= 60.0 {
                        let rate = e.hit_count as f64 / duration;
                        if rate >= 0.05 && rate <= 20.0 {
                            let score = (0.4 + (e.hit_count as f32 / 200.0).min(0.45)).min(0.85);
                            beacon_pairs.push((*src_id, e.dst, score));
                        }
                    }
                }
            }
        }
    }

    if beacon_pairs.is_empty() { return vec![]; }

    // Group all beacon sources into one cluster
    let score = beacon_pairs.iter().map(|(_, _, s)| s).cloned().fold(0.0f32, f32::max);
    let members: Vec<GraphNodeId> = beacon_pairs.iter().flat_map(|(a, b, _)| [*a, *b]).collect::<std::collections::HashSet<_>>().into_iter().collect();
    let src_labels: Vec<String> = members.iter()
        .filter_map(|id| nodes.get(id))
        .filter(|n| n.data.kind() == GraphNodeKind::Host)
        .take(3)
        .map(|n| n.label.clone())
        .collect();

    vec![GraphCluster {
        id:      next_cluster_id(),
        label:   "Beacon Candidates".into(),
        kind:    ClusterKind::BeaconGroup,
        members,
        score,
        summary: format!("{} periodic-flow pair(s): {}", beacon_pairs.len(), src_labels.join(", ")),
    }]
}
