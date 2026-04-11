//! Heuristic attack path reconstruction.
//!
//! Builds plausible suspicious chains across the graph using pattern matching
//! rather than ML. Every path includes a confidence score and explanation.

use std::collections::HashMap;
use crate::model::graph::{GraphNode, GraphEdge, GraphEdgeId, GraphNodeId};
use crate::model::graph_types::{GraphNodeKind, GraphEdgeKind};
use crate::model::graph_evidence::GraphEvidenceRef;

// ─── Attack path ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum AttackPathKind {
    ReconToAuth,
    AuthToLateral,
    BeaconToExfil,
    CredentialReuse,
    CertReuseCluster,
    TokenReuse,
    MultiStageSuspicious,
}

impl std::fmt::Display for AttackPathKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::ReconToAuth          => "Recon→Auth",
            Self::AuthToLateral        => "Auth→Lateral",
            Self::BeaconToExfil        => "Beacon→Exfil",
            Self::CredentialReuse      => "Credential Reuse",
            Self::CertReuseCluster     => "Cert Reuse Cluster",
            Self::TokenReuse           => "Token Reuse",
            Self::MultiStageSuspicious => "Multi-Stage Suspicious",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone)]
pub struct AttackPath {
    pub id:        u64,
    pub nodes:     Vec<GraphNodeId>,
    pub edges:     Vec<GraphEdgeId>,
    pub score:     f32,
    pub summary:   String,
    pub kind:      AttackPathKind,
    pub evidence:  Vec<GraphEvidenceRef>,
    pub why:       String,
}

// ─── Path builder ─────────────────────────────────────────────────────────────

static PATH_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_path_id() -> u64 { PATH_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed) }

pub fn reconstruct_paths(
    nodes:     &HashMap<GraphNodeId, GraphNode>,
    edges:     &HashMap<GraphEdgeId, GraphEdge>,
    out_edges: &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
) -> Vec<AttackPath> {
    let mut paths = Vec::new();

    paths.extend(find_credential_reuse_paths(nodes, edges, out_edges));
    paths.extend(find_ioc_cluster_paths(nodes, edges, out_edges));
    paths.extend(find_cert_reuse_paths(nodes, edges, out_edges));
    paths.extend(find_alert_chain_paths(nodes, edges, out_edges));
    paths.extend(find_beacon_paths(nodes, edges, out_edges));

    // Sort by score descending
    paths.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    paths.truncate(50);
    paths
}

// ─── Credential reuse: same credential node connected to multiple hosts ───────

fn find_credential_reuse_paths(
    nodes:     &HashMap<GraphNodeId, GraphNode>,
    edges:     &HashMap<GraphEdgeId, GraphEdge>,
    out_edges: &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
) -> Vec<AttackPath> {
    let mut paths = Vec::new();
    let cred_nodes: Vec<_> = nodes.values()
        .filter(|n| n.data.kind() == GraphNodeKind::Credential)
        .collect();

    for cred in cred_nodes {
        // Count distinct host destinations
        let mut dst_hosts: Vec<GraphNodeId> = Vec::new();
        let mut edge_ids: Vec<GraphEdgeId> = Vec::new();
        if let Some(eids) = out_edges.get(&cred.id) {
            for &eid in eids {
                if let Some(e) = edges.get(&eid) {
                    if let Some(n) = nodes.get(&e.dst) {
                        if n.data.kind() == GraphNodeKind::Host && !dst_hosts.contains(&e.dst) {
                            dst_hosts.push(e.dst);
                            edge_ids.push(eid);
                        }
                    }
                }
            }
        }
        if dst_hosts.len() >= 2 {
            let score = (0.4 + dst_hosts.len() as f32 * 0.15).min(0.95);
            let mut path_nodes = vec![cred.id];
            path_nodes.extend_from_slice(&dst_hosts);
            let evidence: Vec<GraphEvidenceRef> = cred.evidence.clone();
            paths.push(AttackPath {
                id:      next_path_id(),
                nodes:   path_nodes,
                edges:   edge_ids,
                score,
                summary: format!("Credential '{}' reused across {} hosts", cred.label, dst_hosts.len()),
                kind:    AttackPathKind::CredentialReuse,
                evidence,
                why:     format!("Same credential observed authenticating to {} distinct endpoints", dst_hosts.len()),
            });
        }
    }
    paths
}

// ─── IOC cluster: multiple hosts matching same IOC ─────────────────────────────

fn find_ioc_cluster_paths(
    nodes:     &HashMap<GraphNodeId, GraphNode>,
    edges:     &HashMap<GraphEdgeId, GraphEdge>,
    out_edges: &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
) -> Vec<AttackPath> {
    let mut paths = Vec::new();
    let ioc_nodes: Vec<_> = nodes.values()
        .filter(|n| n.data.kind() == GraphNodeKind::IOC)
        .collect();

    for ioc in ioc_nodes {
        let mut src_hosts: Vec<GraphNodeId> = Vec::new();
        let mut edge_ids: Vec<GraphEdgeId> = Vec::new();
        // incoming edges (host → ioc via MatchesIoc)
        for (_, edge) in edges.iter() {
            if edge.dst == ioc.id && edge.kind == GraphEdgeKind::MatchesIoc {
                if !src_hosts.contains(&edge.src) {
                    src_hosts.push(edge.src);
                    edge_ids.push(edge.id);
                }
            }
        }
        if !src_hosts.is_empty() {
            let score = (0.5 + src_hosts.len() as f32 * 0.1).min(0.95);
            let mut path_nodes = vec![ioc.id];
            path_nodes.extend_from_slice(&src_hosts);
            paths.push(AttackPath {
                id:      next_path_id(),
                nodes:   path_nodes,
                edges:   edge_ids,
                score,
                summary: format!("IOC '{}' matched by {} hosts", ioc.label, src_hosts.len()),
                kind:    AttackPathKind::MultiStageSuspicious,
                evidence: ioc.evidence.clone(),
                why:     "Multiple hosts contacted a known-bad indicator".into(),
            });
        }
        let _ = out_edges; // suppress unused warning
    }
    paths
}

// ─── Certificate reuse: same cert on multiple hosts ───────────────────────────

fn find_cert_reuse_paths(
    nodes:     &HashMap<GraphNodeId, GraphNode>,
    edges:     &HashMap<GraphEdgeId, GraphEdge>,
    out_edges: &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
) -> Vec<AttackPath> {
    let mut paths = Vec::new();
    let cert_nodes: Vec<_> = nodes.values()
        .filter(|n| n.data.kind() == GraphNodeKind::Certificate)
        .collect();

    for cert in cert_nodes {
        let mut presenting_flows: Vec<GraphNodeId> = Vec::new();
        let mut edge_ids: Vec<GraphEdgeId> = Vec::new();
        // flows that present this cert
        for (_, edge) in edges.iter() {
            if edge.dst == cert.id && edge.kind == GraphEdgeKind::PresentsCertificate {
                presenting_flows.push(edge.src);
                edge_ids.push(edge.id);
            }
        }
        if presenting_flows.len() >= 2 {
            let score = (0.45 + presenting_flows.len() as f32 * 0.1).min(0.9);
            let mut path_nodes = vec![cert.id];
            path_nodes.extend_from_slice(&presenting_flows);
            paths.push(AttackPath {
                id:      next_path_id(),
                nodes:   path_nodes,
                edges:   edge_ids,
                score,
                summary: format!("Certificate '{}' reused across {} flows", cert.label, presenting_flows.len()),
                kind:    AttackPathKind::CertReuseCluster,
                evidence: cert.evidence.clone(),
                why:     "Certificate reuse may indicate shared infrastructure".into(),
            });
        }
        let _ = out_edges;
    }
    paths
}

// ─── Alert chains: host with IDS alert also has credential or IOC ─────────────

fn find_alert_chain_paths(
    nodes:     &HashMap<GraphNodeId, GraphNode>,
    edges:     &HashMap<GraphEdgeId, GraphEdge>,
    out_edges: &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
) -> Vec<AttackPath> {
    let mut paths = Vec::new();

    for (_, node) in nodes.iter().filter(|(_, n)| n.data.kind() == GraphNodeKind::Host && n.score > 0.5) {
        let eids = out_edges.get(&node.id).cloned().unwrap_or_default();
        let mut has_alert = false;
        let mut has_ioc   = false;
        let mut has_cred  = false;
        let mut path_edges = Vec::new();
        let mut path_nodes = vec![node.id];

        for eid in &eids {
            if let Some(e) = edges.get(eid) {
                if let Some(n) = nodes.get(&e.dst) {
                    match n.data.kind() {
                        GraphNodeKind::Alert => { has_alert = true; path_edges.push(*eid); path_nodes.push(e.dst); }
                        GraphNodeKind::IOC   => { has_ioc   = true; path_edges.push(*eid); path_nodes.push(e.dst); }
                        GraphNodeKind::Credential => { has_cred = true; path_edges.push(*eid); path_nodes.push(e.dst); }
                        _ => {}
                    }
                }
            }
        }

        let combo = (has_alert as u8) + (has_ioc as u8) + (has_cred as u8);
        if combo >= 2 {
            let score = 0.5 + combo as f32 * 0.15;
            let kinds: Vec<&str> = [
                if has_alert { Some("alert") }   else { None },
                if has_ioc   { Some("IOC") }     else { None },
                if has_cred  { Some("credential") } else { None },
            ].iter().flatten().copied().collect();
            paths.push(AttackPath {
                id:      next_path_id(),
                nodes:   path_nodes,
                edges:   path_edges,
                score,
                summary: format!("Host {} has: {}", node.label, kinds.join(" + ")),
                kind:    AttackPathKind::MultiStageSuspicious,
                evidence: node.evidence.clone(),
                why:     format!("Host combines {} risk indicators", combo),
            });
        }
    }
    paths
}

// ─── Beacon: host with many flows to same destination over time ───────────────

fn find_beacon_paths(
    nodes:     &HashMap<GraphNodeId, GraphNode>,
    edges:     &HashMap<GraphEdgeId, GraphEdge>,
    out_edges: &HashMap<GraphNodeId, Vec<GraphEdgeId>>,
) -> Vec<AttackPath> {
    let mut paths = Vec::new();

    // Count repeated CommunicatesWith edges (high hit_count) as beacon candidates
    for (_, edge) in edges.iter() {
        if edge.kind != GraphEdgeKind::CommunicatesWith { continue; }
        if edge.hit_count < 20 { continue; }  // Minimum repetition threshold

        let duration = edge.last_seen - edge.first_seen;
        if duration < 60.0 { continue; }  // At least 1 minute

        let rate = edge.hit_count as f64 / duration;
        // Periodic beacon: 0.1–5 pkt/sec, sustained > 60s
        if rate < 0.05 || rate > 20.0 { continue; }

        let score = (0.4 + (edge.hit_count as f32 / 200.0).min(0.45)).min(0.85);
        let src_label = nodes.get(&edge.src).map(|n| n.label.as_str()).unwrap_or("?");
        let dst_label = nodes.get(&edge.dst).map(|n| n.label.as_str()).unwrap_or("?");

        paths.push(AttackPath {
            id:      next_path_id(),
            nodes:   vec![edge.src, edge.dst],
            edges:   vec![edge.id],
            score,
            summary: format!("{src_label} → {dst_label}: {} connections over {:.0}s ({:.1}/s)",
                edge.hit_count, duration, rate),
            kind:    AttackPathKind::BeaconToExfil,
            evidence: edge.evidence.clone(),
            why:     format!("Periodic traffic pattern: {:.2} pkt/s for {:.0}s", rate, duration),
        });
        let _ = out_edges;
    }
    paths
}
