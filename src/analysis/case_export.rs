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
    findings:   Vec<FindingRecord<'a>>,
    creds:      Vec<CredRecord<'a>>,
    notebook:   Vec<NoteRecord>,
    incidents:  Vec<IncidentRecord<'a>>,
    evidence:   Vec<EvidenceRecord>,
    processes:  Vec<ProcessRecord<'a>>,
    route_drift: Vec<RouteDriftRecord<'a>>,
    containment: Vec<ContainmentRecord<'a>>,
    latency: Vec<LatencyRecord<'a>>,
    network_identity: Vec<IdentityRecord<'a>>,
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
struct FindingRecord<'a> {
    id: u64,
    source: &'a str,
    title: &'a str,
    severity: &'a str,
    disposition: String,
    priority: u8,
    hit_count: u64,
    first_packet: u64,
    last_packet: u64,
    first_seen: f64,
    last_seen: f64,
    detail: &'a str,
    recommendation: Option<&'a str>,
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
struct IncidentRecord<'a> {
    id: u64,
    source: String,
    detector: &'a str,
    summary: &'a str,
    severity: String,
    attacker: &'a str,
    target: &'a str,
    status: String,
    retained_packets: usize,
}

#[derive(serde::Serialize)]
struct EvidenceRecord {
    incident_id: u64,
    pcap: String,
    metadata: String,
    ndjson: String,
    packets: usize,
}

#[derive(serde::Serialize)]
struct ProcessRecord<'a> {
    pid: u32,
    uid: u32,
    process: &'a str,
    bytes_out: u64,
    bytes_in: u64,
    packets_out: u64,
    packets_in: u64,
}

#[derive(serde::Serialize)]
struct RouteDriftRecord<'a> {
    packet_no: u64,
    subject: &'a str,
    target: &'a str,
    port: u16,
    protocol: &'a str,
    authority: Option<&'a str>,
}

#[derive(serde::Serialize)]
struct ContainmentRecord<'a> {
    incident_id: u64,
    address: Option<String>,
    mode: String,
    status: String,
    expires_seconds: u64,
    detail: &'a str,
    created_at: f64,
}

#[derive(serde::Serialize)]
struct LatencyRecord<'a> {
    kind: String,
    target: &'a str,
    latency_ms: f64,
    packet_no: u64,
}

#[derive(serde::Serialize)]
struct IdentityRecord<'a> {
    address: String,
    asn: Option<&'a str>,
    organization: &'a str,
    source: &'a str,
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

    let findings = app.alert_center.items.iter().map(|item| FindingRecord {
        id: item.id,
        source: &item.source,
        title: &item.title,
        severity: &item.severity,
        disposition: item.disposition.to_string(),
        priority: item.priority,
        hit_count: item.hit_count,
        first_packet: item.first_packet,
        last_packet: item.last_packet,
        first_seen: item.first_seen,
        last_seen: item.last_seen,
        detail: &item.detail,
        recommendation: item.recommendation.as_deref(),
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

    let incidents = app.incidents.incidents.iter().map(|incident| IncidentRecord {
        id: incident.id,
        source: incident.source.to_string(),
        detector: &incident.detector,
        summary: &incident.summary,
        severity: incident.severity.to_string(),
        attacker: &incident.attacker,
        target: &incident.target,
        status: incident.status.to_string(),
        retained_packets: incident.packet_history.len(),
    }).collect();

    let evidence = app.evidence_vault.exports.iter().map(|export| EvidenceRecord {
        incident_id: export.incident_id,
        pcap: export.pcap_path.display().to_string(),
        metadata: export.metadata_path.display().to_string(),
        ndjson: export.ndjson_path.display().to_string(),
        packets: export.packet_count,
    }).collect();

    let processes = app.socket_scope.sorted_traffic().into_iter().map(|usage| ProcessRecord {
        pid: usage.pid,
        uid: usage.uid,
        process: &usage.process,
        bytes_out: usage.bytes_out,
        bytes_in: usage.bytes_in,
        packets_out: usage.packets_out,
        packets_in: usage.packets_in,
    }).collect();

    let route_drift = app.route_ledger.drift.iter().map(|finding| RouteDriftRecord {
        packet_no: finding.packet_no,
        subject: &finding.route.subject,
        target: &finding.route.target,
        port: finding.route.port,
        protocol: &finding.route.protocol,
        authority: finding.route.authority.as_deref(),
    }).collect();

    let containment = app.traffic_latch.actions.iter().map(|action| ContainmentRecord {
        incident_id: action.incident_id,
        address: action.address.map(|address| address.to_string()),
        mode: action.mode.to_string(),
        status: action.status.to_string(),
        expires_seconds: action.expires_seconds,
        detail: &action.detail,
        created_at: action.created_at,
    }).collect();

    let latency = app.wire_pulse.samples.iter().map(|sample| LatencyRecord {
        kind: sample.kind.to_string(),
        target: &sample.target,
        latency_ms: sample.latency_ms,
        packet_no: sample.packet_no,
    }).collect();

    let network_identity = app.net_registry.sorted().into_iter().map(|identity| IdentityRecord {
        address: identity.address.to_string(),
        asn: identity.asn.as_deref(),
        organization: &identity.organization,
        source: &identity.source,
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

    CaseBundle { meta, hosts, ioc_hits, rule_hits, yara, alerts, findings, creds, notebook, incidents, evidence, processes, route_drift, containment, latency, network_identity, graph_meta }
}
