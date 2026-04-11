//! Operator Graph engine — builds a live correlation graph from all analysis subsystems.
//!
//! The engine receives incremental updates and maintains typed nodes/edges with
//! provenance, timestamps, and risk scores. All heavy analysis (paths, clusters,
//! scoring) can be triggered lazily rather than on every packet.

use std::collections::HashMap;
use crate::model::graph::{GraphNode, GraphEdge, GraphEdgeId, GraphNodeId, GraphSnapshot, GraphViewFilter, Timestamp};
use crate::model::graph_types::*;
use crate::model::graph_evidence::GraphEvidenceRef;
use crate::model::evidence::PacketRef;
use crate::analysis::pivot::{PivotSuggestion, pivot_suggestions_for};
use crate::analysis::path_reconstruction::{AttackPath, reconstruct_paths};
use crate::analysis::graph_scoring::score_nodes;
use crate::analysis::graph_cluster::{GraphCluster, compute_clusters};

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
            Self::Adjacency    => write!(f, "Adjacency"),
            Self::Paths        => write!(f, "Paths"),
            Self::Clusters     => write!(f, "Clusters"),
            Self::Evidence     => write!(f, "Evidence"),
        }
    }
}

#[derive(Debug, Default)]
pub struct GraphUiState {
    pub selected_node:    Option<GraphNodeId>,
    pub list_scroll:      usize,
    pub neighbor_scroll:  usize,
    pub detail_scroll:    usize,
    pub mode:             GraphUiModeState,
    pub pivot_history:    Vec<GraphNodeId>,
    pub filter:           GraphViewFilter,
    pub search:           String,
    pub searching:        bool,
    pub path_selected:    usize,
    pub cluster_selected: usize,
    pub evidence_scroll:  usize,
    // High-water marks for incremental sync from other engines
    pub synced_alerts:    usize,
    pub synced_ioc_hits:  usize,
    pub synced_creds:     usize,
    pub synced_objects:   usize,
    pub synced_tls:       usize,
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
            Self::Adjacency    => "Adjacency",
            Self::Paths        => "Paths",
            Self::Clusters     => "Clusters",
            Self::Evidence     => "Evidence",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            Self::Neighborhood => Self::Adjacency,
            Self::Adjacency    => Self::Paths,
            Self::Paths        => Self::Clusters,
            Self::Clusters     => Self::Evidence,
            Self::Evidence     => Self::Neighborhood,
        }
    }
}

// ─── Graph engine ─────────────────────────────────────────────────────────────

pub struct OperatorGraphEngine {
    /// All nodes by ID.
    nodes:          HashMap<GraphNodeId, GraphNode>,
    /// All edges by ID.
    edges:          HashMap<GraphEdgeId, GraphEdge>,
    /// Normalized key → node ID (for deduplication).
    key_index:      HashMap<String, GraphNodeId>,
    /// Outgoing edges per node.
    out_edges:      HashMap<GraphNodeId, Vec<GraphEdgeId>>,
    /// Incoming edges per node.
    in_edges:       HashMap<GraphNodeId, Vec<GraphEdgeId>>,
    /// (src, dst, kind_str) → edge ID (prevents duplicate edges).
    edge_index:     HashMap<(GraphNodeId, GraphNodeId, String), GraphEdgeId>,
    /// Cached attack paths (rebuilt lazily).
    pub paths:      Vec<AttackPath>,
    /// Cached clusters (rebuilt lazily).
    pub clusters:   Vec<GraphCluster>,
    /// Cached pivot suggestions for the last queried node.
    pub pivots:     Vec<PivotSuggestion>,
    pub pivots_for: Option<GraphNodeId>,
    /// Stats
    pub total_events: u64,
}

impl Default for OperatorGraphEngine {
    fn default() -> Self {
        Self {
            nodes:        HashMap::new(),
            edges:        HashMap::new(),
            key_index:    HashMap::new(),
            out_edges:    HashMap::new(),
            in_edges:     HashMap::new(),
            edge_index:   HashMap::new(),
            paths:        Vec::new(),
            clusters:     Vec::new(),
            pivots:       Vec::new(),
            pivots_for:   None,
            total_events: 0,
        }
    }
}

impl OperatorGraphEngine {
    // ─── Core node/edge management ────────────────────────────────────────────

    /// Insert or update a node by its normalized key. Returns the node ID.
    pub fn ensure_node(&mut self, key: String, label: String, ts: Timestamp, data: GraphNodeData) -> GraphNodeId {
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
        if let Some(n) = self.nodes.get_mut(&id) { n.add_evidence(ev); }
    }

    pub fn add_edge_evidence(&mut self, id: GraphEdgeId, ev: GraphEvidenceRef) {
        if let Some(e) = self.edges.get_mut(&id) { e.add_evidence(ev); }
    }

    pub fn tag_node(&mut self, id: GraphNodeId, tag: impl Into<String>) {
        if let Some(n) = self.nodes.get_mut(&id) { n.add_tag(tag); }
    }

    // ─── Public queries ───────────────────────────────────────────────────────

    pub fn get_node(&self, id: GraphNodeId) -> Option<&GraphNode> { self.nodes.get(&id) }
    pub fn get_edge(&self, id: GraphEdgeId) -> Option<&GraphEdge> { self.edges.get(&id) }

    pub fn node_count(&self) -> usize { self.nodes.len() }
    pub fn edge_count(&self) -> usize { self.edges.len() }

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
        if let Some(out) = self.out_edges.get(&id) { v.extend_from_slice(out); }
        if let Some(inc) = self.in_edges.get(&id)  { v.extend_from_slice(inc); }
        v.dedup();
        v
    }

    pub fn nodes_by_kind(&self, kind: &GraphNodeKind) -> Vec<GraphNodeId> {
        self.nodes.values()
            .filter(|n| &n.kind() == kind)
            .map(|n| n.id)
            .collect()
    }

    /// All nodes sorted by score descending.
    pub fn all_nodes_sorted(&self) -> Vec<&GraphNode> {
        let mut v: Vec<_> = self.nodes.values().collect();
        v.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        v
    }

    /// Filtered snapshot respecting GraphViewFilter.
    pub fn filtered_snapshot(&self, filter: &GraphViewFilter) -> GraphSnapshot {
        let node_ids: Vec<_> = self.nodes.values()
            .filter(|n| filter.node_passes(n))
            .map(|n| n.id)
            .collect();
        let node_set: std::collections::HashSet<_> = node_ids.iter().copied().collect();
        let edge_ids: Vec<_> = self.edges.values()
            .filter(|e| node_set.contains(&e.src) && node_set.contains(&e.dst))
            .map(|e| e.id)
            .collect();
        GraphSnapshot { node_ids, edge_ids }
    }

    // ─── Packet-level ingestion ───────────────────────────────────────────────

    /// Called per-packet to create/update Host → Host flow relationships.
    pub fn on_packet(
        &mut self,
        src: &str, dst: &str,
        proto: &str,
        _sport: Option<u16>, dport: Option<u16>,
        ts: Timestamp, bytes: u64, pkt_no: u64,
    ) {
        if src.is_empty() || dst.is_empty() || src == "0.0.0.0" || dst == "0.0.0.0" { return; }

        let src_id = self.ensure_node(
            format!("Host:{src}"), src.to_string(), ts,
            GraphNodeData::Host(HostNodeData { ips: vec![src.to_string()], ..Default::default() }),
        );
        let dst_id = self.ensure_node(
            format!("Host:{dst}"), dst.to_string(), ts,
            GraphNodeData::Host(HostNodeData { ips: vec![dst.to_string()], ..Default::default() }),
        );

        let pkt_ev = GraphEvidenceRef::Packet(PacketRef(pkt_no));
        self.add_node_evidence(src_id, pkt_ev.clone());
        self.add_node_evidence(dst_id, pkt_ev.clone());

        let eid = self.ensure_edge(src_id, dst_id, GraphEdgeKind::CommunicatesWith, ts, 1.0, bytes);
        if let Some(e) = self.edges.get_mut(&eid) {
            e.meta.protocol = Some(proto.to_string());
            e.meta.port = dport;
        }
        self.add_edge_evidence(eid, pkt_ev);

        // Service node for destination port
        if let Some(port) = dport {
            let svc_key = format!("Service:{dst}:{port}/{proto}");
            let svc_label = format!("{dst}:{port}/{proto}");
            let svc_id = self.ensure_node(svc_key, svc_label, ts, GraphNodeData::Service(ServiceNodeData {
                protocol: proto.to_string(),
                port,
                host_ip: dst.to_string(),
                role: known_service_role(port, proto),
            }));
            self.ensure_edge(dst_id, svc_id, GraphEdgeKind::BelongsToHost, ts, 1.0, 0);
            self.ensure_edge(src_id, svc_id, GraphEdgeKind::UsesService, ts, 1.0, bytes);
        }

        self.total_events += 1;
    }

    // ─── Higher-level ingestion ───────────────────────────────────────────────

    pub fn on_credential(
        &mut self,
        username: Option<&str>, scheme: &str, cleartext: bool,
        src_ip: &str, dst_ip: &str,
        ts: Timestamp, pkt_no: u64,
    ) {
        if src_ip.is_empty() { return; }
        let uname = username.unwrap_or("unknown");
        let key = format!("Cred:{scheme}:{uname}:{dst_ip}");
        let label = format!("{scheme}://{uname}@{dst_ip}");
        let cred_id = self.ensure_node(key, label, ts, GraphNodeData::Credential(CredentialNodeData {
            cred_type:  scheme.to_string(),
            username:   username.map(str::to_string),
            pw_preview: "***".into(),
            scheme:     scheme.to_string(),
            cleartext,
            confidence: if cleartext { 0.95 } else { 0.7 },
        }));

        let src_id = self.ensure_node(
            format!("Host:{src_ip}"), src_ip.to_string(), ts,
            GraphNodeData::Host(HostNodeData { ips: vec![src_ip.to_string()], ..Default::default() }),
        );
        let dst_id = self.ensure_node(
            format!("Host:{dst_ip}"), dst_ip.to_string(), ts,
            GraphNodeData::Host(HostNodeData { ips: vec![dst_ip.to_string()], ..Default::default() }),
        );
        self.ensure_edge(src_id, cred_id, GraphEdgeKind::AuthenticatedWith, ts, 0.9, 0);
        self.ensure_edge(cred_id, dst_id, GraphEdgeKind::AuthenticatedWith, ts, 0.9, 0);
        self.add_node_evidence(cred_id, GraphEvidenceRef::Packet(PacketRef(pkt_no)));

        // High-risk tag for cleartext
        if cleartext { self.tag_node(cred_id, "cleartext-credential"); }
    }

    pub fn on_tls_session(&mut self, flow_id: &str, sni: Option<&str>, fingerprint: &str, ts: Timestamp) {
        if fingerprint.is_empty() { return; }
        // Certificate node
        let cert_key = format!("Cert:{fingerprint}");
        let cert_label = sni.map(|s| format!("cert:{s}")).unwrap_or_else(|| format!("cert:{}", &fingerprint[..8.min(fingerprint.len())]));
        let cert_id = self.ensure_node(cert_key, cert_label, ts, GraphNodeData::Certificate(CertificateNodeData {
            fingerprint: fingerprint.to_string(),
            subject:     sni.unwrap_or("unknown").to_string(),
            ..Default::default()
        }));

        // SNI identity node
        if let Some(name) = sni {
            let ident_key = format!("Identity:tls-sni:{name}");
            let ident_id = self.ensure_node(ident_key, name.to_string(), ts, GraphNodeData::Identity(IdentityNodeData {
                name: name.to_string(),
                kind: "tls-sni".into(),
                resolved_ip: None,
            }));
            self.ensure_edge(cert_id, ident_id, GraphEdgeKind::ResolvesTo, ts, 0.9, 0);
        }

        // Link flow nodes to certificate
        let flow_key = format!("Flow:{flow_id}");
        if let Some(&flow_node_id) = self.key_index.get(&flow_key) {
            self.ensure_edge(flow_node_id, cert_id, GraphEdgeKind::PresentsCertificate, ts, 1.0, 0);
        }
    }

    pub fn on_ids_alert(&mut self, signature: &str, severity: &str, src_ip: &str, dst_ip: &str, pkt_no: u64, ts: Timestamp) {
        let key = format!("Alert:{signature}:{pkt_no}");
        let label = format!("[{severity}] {signature}");
        let alert_id = self.ensure_node(key, label, ts, GraphNodeData::Alert(AlertNodeData {
            signature: signature.to_string(),
            severity:  severity.to_string(),
            detail:    format!("{src_ip} → {dst_ip}"),
            pkt_no,
        }));
        self.add_node_evidence(alert_id, GraphEvidenceRef::Alert(pkt_no));

        for ip in [src_ip, dst_ip].iter().filter(|ip| !ip.is_empty()) {
            let host_id = self.ensure_node(
                format!("Host:{ip}"), ip.to_string(), ts,
                GraphNodeData::Host(HostNodeData { ips: vec![ip.to_string()], ..Default::default() }),
            );
            self.ensure_edge(host_id, alert_id, GraphEdgeKind::TriggersAlert, ts, 0.95, 0);
            self.tag_node(host_id, format!("alert:{}", severity.to_lowercase()));
        }
    }

    pub fn on_ioc_hit(&mut self, value: &str, kind: &str, context: &str, pkt_no: u64, ts: Timestamp, src_ip: &str) {
        let key = format!("IOC:{kind}:{value}");
        let label = format!("[{kind}] {value}");
        let ioc_id = self.ensure_node(key, label, ts, GraphNodeData::IOC(IocNodeData {
            ioc_kind:    kind.to_string(),
            value:       value.to_string(),
            description: context.to_string(),
            source:      "ioc-engine".into(),
        }));
        self.add_node_evidence(ioc_id, GraphEvidenceRef::IocHit(pkt_no));
        self.tag_node(ioc_id, "ioc-match");

        if !src_ip.is_empty() {
            let host_id = self.ensure_node(
                format!("Host:{src_ip}"), src_ip.to_string(), ts,
                GraphNodeData::Host(HostNodeData { ips: vec![src_ip.to_string()], ..Default::default() }),
            );
            self.ensure_edge(host_id, ioc_id, GraphEdgeKind::MatchesIoc, ts, 0.95, 0);
            self.tag_node(host_id, "ioc-associated");
        }
    }

    pub fn on_rule_hit(&mut self, rule_id: &str, rule_name: &str, action: &str, pkt_no: u64, ts: Timestamp) {
        let key = format!("RuleHit:{rule_id}:{pkt_no}");
        let label = format!("Rule: {rule_name}");
        let hit_id = self.ensure_node(key, label, ts, GraphNodeData::RuleHit(RuleHitNodeData {
            rule_id:   rule_id.to_string(),
            rule_name: rule_name.to_string(),
            pkt_no,
            action:    action.to_string(),
        }));
        self.add_node_evidence(hit_id, GraphEvidenceRef::RuleHit(pkt_no));
    }

    pub fn on_carved_object(&mut self, obj_id: u64, mime: &str, sha256: &str, source: &str, size: usize, ts: Timestamp) {
        let key = format!("File:{}", if sha256.is_empty() { format!("id:{obj_id}") } else { sha256.to_string() });
        let label = format!("{} ({})", mime, human_size(size));
        let file_id = self.ensure_node(key, label, ts, GraphNodeData::FileObject(FileObjectNodeData {
            filename:  format!("object_{obj_id}"),
            mime:      mime.to_string(),
            sha256:    sha256.to_string(),
            size,
            source:    source.to_string(),
            yara_hits: Vec::new(),
        }));
        self.add_node_evidence(file_id, GraphEvidenceRef::Object(crate::model::evidence::ObjectRef(obj_id)));
        self.tag_node(file_id, "carved");

        // Link to source flow if we can identify it
        let flow_key = format!("Flow:{source}");
        if let Some(&flow_id) = self.key_index.get(&flow_key) {
            self.ensure_edge(file_id, flow_id, GraphEdgeKind::ExtractedFrom, ts, 0.85, 0);
        }
    }

    // ─── Lazy intelligence ────────────────────────────────────────────────────

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
        self.pivots = pivot_suggestions_for(node_id, &self.nodes, &self.edges, &self.out_edges, &self.in_edges);
        self.pivots_for = Some(node_id);
    }

    // ─── Persistence helpers ──────────────────────────────────────────────────

    pub fn all_nodes(&self) -> impl Iterator<Item = &GraphNode> { self.nodes.values() }
    pub fn all_edges(&self) -> impl Iterator<Item = &GraphEdge> { self.edges.values() }

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
    if proto != "TCP" && proto != "UDP" { return None; }
    let role = match port {
        21   => "FTP",
        22   => "SSH",
        23   => "Telnet",
        25   => "SMTP",
        53   => "DNS",
        80   => "HTTP",
        110  => "POP3",
        143  => "IMAP",
        443  => "HTTPS",
        445  => "SMB",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        6379 => "Redis",
        8080 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        _    => return None,
    };
    Some(role.to_string())
}

fn human_size(bytes: usize) -> String {
    if bytes < 1024 { format!("{bytes}B") }
    else if bytes < 1_048_576 { format!("{:.1}KB", bytes as f64 / 1024.0) }
    else { format!("{:.1}MB", bytes as f64 / 1_048_576.0) }
}
