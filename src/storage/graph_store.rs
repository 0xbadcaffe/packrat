//! Graph persistence and export (JSON, CSV, Markdown).

use std::path::{Path, PathBuf};
use anyhow::Result;

use crate::analysis::operator_graph::OperatorGraphEngine;
use crate::analysis::path_reconstruction::AttackPath;
use crate::analysis::graph_cluster::GraphCluster;

// ─── JSON export ──────────────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
pub struct GraphExport {
    pub version:  u32,
    pub exported: f64,
    pub nodes:    Vec<NodeExport>,
    pub edges:    Vec<EdgeExport>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct NodeExport {
    pub id:         u64,
    pub key:        String,
    pub label:      String,
    pub kind:       String,
    pub score:      f32,
    pub first_seen: f64,
    pub last_seen:  f64,
    pub hit_count:  u64,
    pub tags:       Vec<String>,
    pub score_why:  String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct EdgeExport {
    pub id:         u64,
    pub src:        u64,
    pub dst:        u64,
    pub kind:       String,
    pub confidence: f32,
    pub first_seen: f64,
    pub last_seen:  f64,
    pub hit_count:  u64,
    pub pkt_count:  u64,
    pub byte_count: u64,
}

pub fn export_json(engine: &OperatorGraphEngine, path: impl AsRef<Path>) -> Result<PathBuf> {
    let path = path.as_ref();
    let nodes: Vec<NodeExport> = engine.all_nodes().map(|n| NodeExport {
        id:         n.id,
        key:        n.key.clone(),
        label:      n.label.clone(),
        kind:       n.kind().to_string(),
        score:      n.score,
        first_seen: n.first_seen,
        last_seen:  n.last_seen,
        hit_count:  n.hit_count,
        tags:       n.tags.iter().cloned().collect(),
        score_why:  n.score_why.clone(),
    }).collect();

    let edges: Vec<EdgeExport> = engine.all_edges().map(|e| EdgeExport {
        id:         e.id,
        src:        e.src,
        dst:        e.dst,
        kind:       e.kind.to_string(),
        confidence: e.confidence,
        first_seen: e.first_seen,
        last_seen:  e.last_seen,
        hit_count:  e.hit_count,
        pkt_count:  e.meta.pkt_count,
        byte_count: e.meta.byte_count,
    }).collect();

    let export = GraphExport {
        version: 1,
        exported: now(),
        nodes,
        edges,
    };

    let json = serde_json::to_string_pretty(&export)?;
    std::fs::write(path, json)?;
    Ok(path.to_path_buf())
}

// ─── CSV export ───────────────────────────────────────────────────────────────

pub fn export_csv_nodes(engine: &OperatorGraphEngine, path: impl AsRef<Path>) -> Result<PathBuf> {
    let path = path.as_ref();
    let mut out = String::from("id,kind,label,score,first_seen,last_seen,hit_count,tags\n");
    let mut nodes: Vec<_> = engine.all_nodes().collect();
    nodes.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    for n in &nodes {
        let tags = n.tags.iter().cloned().collect::<Vec<_>>().join(";");
        out.push_str(&format!("{},{},{},{:.3},{:.0},{:.0},{},{}\n",
            n.id, n.kind(), csv_escape(&n.label), n.score, n.first_seen, n.last_seen, n.hit_count, tags));
    }
    std::fs::write(path, out)?;
    Ok(path.to_path_buf())
}

pub fn export_csv_edges(engine: &OperatorGraphEngine, path: impl AsRef<Path>) -> Result<PathBuf> {
    let path = path.as_ref();
    let mut out = String::from("id,src,dst,kind,confidence,hit_count,pkt_count,byte_count\n");
    for e in engine.all_edges() {
        out.push_str(&format!("{},{},{},{},{:.2},{},{},{}\n",
            e.id, e.src, e.dst, e.kind, e.confidence, e.hit_count, e.meta.pkt_count, e.meta.byte_count));
    }
    std::fs::write(path, out)?;
    Ok(path.to_path_buf())
}

// ─── Markdown summary ─────────────────────────────────────────────────────────

pub fn export_markdown(
    engine:   &OperatorGraphEngine,
    paths:    &[AttackPath],
    clusters: &[GraphCluster],
    path:     impl AsRef<Path>,
) -> Result<PathBuf> {
    let fpath = path.as_ref();
    use std::fmt::Write;
    let mut md = String::new();

    writeln!(md, "# Packrat Operator Graph Report\n")?;
    writeln!(md, "**Generated:** {:.0}  **Nodes:** {}  **Edges:** {}\n",
        now(), engine.node_count(), engine.edge_count())?;

    // Top risky nodes
    writeln!(md, "## Top Risk Nodes\n")?;
    writeln!(md, "| Rank | Kind | Label | Score | Why |")?;
    writeln!(md, "|------|------|-------|-------|-----|")?;
    let top_nodes: Vec<_> = {
        let mut v: Vec<_> = engine.all_nodes().collect();
        v.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        v.into_iter().take(10).collect()
    };
    for (i, n) in top_nodes.iter().enumerate() {
        writeln!(md, "| {} | {} | {} | {:.2} | {} |",
            i + 1, n.kind(), md_escape(&n.label), n.score, md_escape(&n.score_why))?;
    }
    writeln!(md)?;

    // Suspicious paths
    writeln!(md, "## Suspicious Paths\n")?;
    for (i, path) in paths.iter().take(10).enumerate() {
        writeln!(md, "### {}. {} (score: {:.2})\n", i + 1, path.kind, path.score)?;
        writeln!(md, "**Summary:** {}\n", path.summary)?;
        writeln!(md, "**Why:** {}\n", path.why)?;
        writeln!(md, "**Nodes:** {}\n", path.nodes.len())?;
    }

    // Clusters
    writeln!(md, "## Clusters\n")?;
    for (i, c) in clusters.iter().take(10).enumerate() {
        writeln!(md, "{}. **{}** ({}) — {} — {:.2}\n",
            i + 1, c.label, c.kind, c.summary, c.score)?;
    }

    std::fs::write(fpath, md)?;
    Ok(fpath.to_path_buf())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
