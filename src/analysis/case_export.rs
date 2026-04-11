//! Case bundle export — collect all analysis state and write a structured JSON report.
//!
//! The bundle is a single JSON file containing:
//!   - capture metadata (interface, duration, packet count, bytes)
//!   - host inventory (ip, geo, ports, protocols, os_guess, alert_count)
//!   - IOC hits
//!   - rule hits
//!   - YARA scan results
//!   - security alerts and credentials (redacted values)
//!   - analyst notebook entries
//!   - operator graph summary (node count, edge count, top-scored nodes)

use std::path::Path;
use crate::app::App;

// ─── Bundle struct (serde-serialised) ────────────────────────────────────────

#[derive(serde::Serialize)]
struct CaseBundle<'a> {
    meta:       CaptureMeta<'a>,
    hosts:      Vec<HostRecord<'a>>,
    ioc_hits:   Vec<IocHitRecord<'a>>,
    rule_hits:  Vec<RuleHitRecord<'a>>,
    yara:       Vec<YaraRecord<'a>>,
    alerts:     Vec<AlertRecord>,
    creds:      Vec<CredRecord<'a>>,
    notebook:   Vec<NoteRecord>,
    graph_meta: GraphMeta,
}

#[derive(serde::Serialize)]
struct CaptureMeta<'a> {
    iface:         &'a str,
    packets_total: u64,
    bytes_total:   u64,
    duration_sec:  f64,
    flows:         usize,
    streams:       usize,
}

#[derive(serde::Serialize)]
struct HostRecord<'a> {
    ip:          &'a str,
    geo:         &'a str,
    mac:         Option<&'a str>,
    hostnames:   Vec<&'a str>,
    protocols:   Vec<&'a str>,
    ports:       Vec<u16>,
    bytes_out:   u64,
    bytes_in:    u64,
    pkts_out:    u64,
    pkts_in:     u64,
    alerts:      u32,
    os_guess:    Option<&'a str>,
}

#[derive(serde::Serialize)]
struct IocHitRecord<'a> {
    kind:    String,
    value:   &'a str,
    context: &'a str,
    pkt_no:  u64,
}

#[derive(serde::Serialize)]
struct RuleHitRecord<'a> {
    rule_id:   &'a str,
    rule_name: &'a str,
    message:   &'a str,
    pkt_no:    u64,
}

#[derive(serde::Serialize)]
struct YaraRecord<'a> {
    target:    &'a str,
    rules_hit: Vec<String>,
    matches:   usize,
}

#[derive(serde::Serialize)]
struct AlertRecord {
    signature: String,
    severity:  String,
    pkt_no:    u64,
}

#[derive(serde::Serialize)]
struct CredRecord<'a> {
    proto: &'a str,
    kind:  &'a str,
}

#[derive(serde::Serialize)]
struct NoteRecord {
    id:        u64,
    text:      String,
    timestamp: f64,
}

#[derive(serde::Serialize)]
struct GraphMeta {
    nodes:         usize,
    edges:         usize,
    top_scored:    Vec<TopNode>,
}

#[derive(serde::Serialize)]
struct TopNode {
    label: String,
    score: f32,
    why:   String,
}

// ─── Export logic ─────────────────────────────────────────────────────────────

/// Write a full case bundle JSON to `path`. Returns the path on success.
pub fn export(app: &App, path: &Path) -> Result<String, String> {
    let bundle = build(app);
    let json = serde_json::to_string_pretty(&bundle)
        .map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(path, &json)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(path.display().to_string())
}

/// Build a case bundle path with a timestamp and write it next to the binary.
pub fn export_auto(app: &App) -> Result<String, String> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_secs();
    let filename = format!("packrat_case_{ts}.json");
    // Try CWD, then ~/
    let candidates = [
        std::path::PathBuf::from(&filename),
        dirs_next::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join(&filename),
    ];
    for path in &candidates {
        if let Ok(s) = export(app, path) { return Ok(s); }
    }
    Err("could not write case bundle to any location".into())
}

fn build(app: &App) -> CaseBundle<'_> {
    // Capture metadata
    let duration = app.packets.back().map(|p| p.timestamp).unwrap_or(0.0);
    let meta = CaptureMeta {
        iface:         &app.selected_iface,
        packets_total: app.packet_counter,
        bytes_total:   app.total_bytes,
        duration_sec:  duration,
        flows:         app.flow_tracker.flows.len(),
        streams:       app.streams.len(),
    };

    // Hosts
    let hosts: Vec<HostRecord<'_>> = app.hosts.all().iter().map(|h| {
        let mut ports: Vec<u16> = h.open_ports.iter().copied().collect();
        ports.sort();
        let mut protos: Vec<&str> = h.protocols.iter().map(|s| s.as_str()).collect();
        protos.sort();
        let mut hnames: Vec<&str> = h.hostnames.iter().map(|s| s.as_str()).collect();
        hnames.sort();
        HostRecord {
            ip:        &h.ip,
            geo:       h.geo.as_deref().unwrap_or("??"),
            mac:       h.mac.as_deref(),
            hostnames: hnames,
            protocols: protos,
            ports,
            bytes_out: h.bytes_out,
            bytes_in:  h.bytes_in,
            pkts_out:  h.pkts_out,
            pkts_in:   h.pkts_in,
            alerts:    h.alert_count,
            os_guess:  h.os_guess.as_deref(),
        }
    }).collect();

    // IOC hits
    let ioc_hits: Vec<IocHitRecord<'_>> = app.ioc_engine.hits.iter().map(|h| IocHitRecord {
        kind:    h.ioc.kind.to_string(),
        value:   &h.ioc.value,
        context: &h.context,
        pkt_no:  h.pkt_no,
    }).collect();

    // Rule hits
    let rule_hits: Vec<RuleHitRecord<'_>> = app.rule_engine.hits.iter().map(|h| RuleHitRecord {
        rule_id:   &h.rule_id,
        rule_name: &h.rule_name,
        message:   &h.message,
        pkt_no:    h.pkt_no,
    }).collect();

    // YARA results
    let yara: Vec<YaraRecord<'_>> = app.yara_engine.results.iter().map(|r| YaraRecord {
        target:    &r.target_label,
        rules_hit: r.rule_names(),
        matches:   r.matches.len(),
    }).collect();

    // Security alerts
    let alerts: Vec<AlertRecord> = app.security.ids_alerts.iter().map(|a| AlertRecord {
        signature: a.signature.to_string(),
        severity:  a.severity.to_string(),
        pkt_no:    a.pkt_no,
    }).collect();

    // Credentials (redacted — only protocol and kind, no values)
    let creds: Vec<CredRecord<'_>> = app.credentials.iter().map(|c| CredRecord {
        proto: &c.proto,
        kind:  c.kind,
    }).collect();

    // Notebook
    let notebook: Vec<NoteRecord> = app.notebook.all().iter().map(|n| NoteRecord {
        id:        n.id,
        text:      n.text.clone(),
        timestamp: n.timestamp,
    }).collect();

    // Operator graph summary
    let graph = &app.operator_graph;
    let mut top: Vec<TopNode> = graph.all_nodes_sorted()
        .into_iter()
        .map(|n| TopNode {
            label: n.label.clone(),
            score: n.score,
            why:   n.score_why.clone(),
        })
        .collect();
    top.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    top.truncate(20);

    let graph_meta = GraphMeta {
        nodes:      graph.node_count(),
        edges:      graph.edge_count(),
        top_scored: top,
    };

    CaseBundle { meta, hosts, ioc_hits, rule_hits, yara, alerts, creds, notebook, graph_meta }
}
