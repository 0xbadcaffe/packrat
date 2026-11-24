//! Offline, passive analysis adapter. Never initializes a terminal or containment.

use std::collections::VecDeque;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use packrat_tui::engine::{AnalysisCore, PacketDisposition};
use packrat_tui::analysis::vlan::VlanPolicy;
use packrat_tui::net::packet::CaptureMetadata;
use packrat_tui::pcap_replay::stream_pcap;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

#[path = "packrat-analyze/alerts.rs"]
mod alerts;
use alerts::ReplayAlerts;

fn event(output: &mut impl Write, value: &impl Serialize) -> Result<(), String> {
    serde_json::to_writer(&mut *output, value).map_err(|error| error.to_string())?;
    output.write_all(b"\n").map_err(|error| error.to_string())
}

fn analyze(
    path: &Path,
    helper: Option<std::path::PathBuf>,
    alerts_only: bool,
    allow_truncated: bool,
    vlan_policy: VlanPolicy,
    mut replay: ReplayAlerts,
    output: &mut impl Write,
) -> Result<(), String> {
    let mut core = AnalysisCore::default();
    core.quic_scope.decode_helper_path = helper;
    core.vlan_intel.policy = vlan_policy;
    // Only recent packets are supplied as pre-incident context. Capture bytes
    // remain in the original file; the input is never loaded wholesale.
    let mut history = VecDeque::with_capacity(256);
    let mut analyzed = 0u64;
    let mut skipped = 0u64;
    let mut truncated_frames = 0u64;
    let mut coverage = Sha256::new();
    let packets = stream_pcap(path, |packet| {
        let truncated = packet.capture.as_ref().is_some_and(CaptureMetadata::truncated);
        truncated_frames += u64::from(truncated);
        let outcome = core.analyze_with_history(&packet, history.iter().cloned());
        let accepted = outcome.disposition == PacketDisposition::Analyzed;
        // v1 hashes the flags in capture order: bit 0 analyzed, bit 1 truncated.
        coverage.update([u8::from(accepted) | (u8::from(truncated) << 1)]);
        if !accepted {
            skipped += 1;
            event(
                output,
                &json!({"type": "skipped_packet", "packet": packet.no,
                "reason": outcome.disposition}),
            )?;
            return Ok(());
        }
        analyzed += 1;
        for alert in core.alert_center.drain_pending_exports() {
            let opening = replay.observe(&alert);
            if alerts_only {
                event(output, &json!({"type": "alert", "schema_version": 1, "opening": opening, "alert": alert}))?;
            }
        }
        if !alerts_only {
            for notice in outcome.incidents {
                event(
                    output,
                    &json!({"type": "incident", "packet": packet.no, "notice": notice}),
                )?;
            }
        }
        if history.len() == 256 {
            history.pop_front();
        }
        history.push_back(packet);
        Ok(())
    })?;
    let frame_coverage_sha256_v1 = format!("{:x}", coverage.finalize());
    let dns_capacity = core.security.dns_capacity_stats();
    let evaluation = replay.evaluate(
        analyzed > 0 && skipped == 0 && (truncated_frames == 0 || allow_truncated),
        dns_capacity,
        core.streams.evicted_streams(),
    );
    if alerts_only {
        event(
            output,
            &json!({
                "type": "summary", "packets": packets, "analyzed": analyzed, "skipped": skipped,
                "truncated_frames": truncated_frames, "allow_truncated": allow_truncated,
                "dns_capacity": dns_capacity,
                "retained_streams": core.streams.len(), "evicted_streams": core.streams.evicted_streams(),
                "frame_coverage_sha256_v1": frame_coverage_sha256_v1,
                "alert_scope": "grouped_alerts", "alerts_opened": replay.opened,
                "alert_snapshots": replay.snapshots, "rule_counts": replay.rule_counts,
                "alert_expectations": evaluation, "containment": "disabled"
            }),
        )?;
        output.flush().map_err(|error| error.to_string())?;
        if evaluation.as_ref().is_some_and(|evaluation| evaluation.verdict != "passed") {
            return Err("Alert expectations did not pass; see the replay summary".into());
        }
        return Ok(());
    }
    let mut exchanges = 0usize;
    let mut http2_exchanges = 0usize;
    core.refresh_graph();
    for stream in core.streams.all() {
        let id = stream.key.id();
        if packrat_tui::analysis::transactions::is_http2(stream) {
            let report = core
                .http2_transactions(&id)
                .ok_or("Retained stream disappeared")?;
            http2_exchanges += report.transactions.len();
            event(
                output,
                &json!({"type": "http2_conversation", "stream_id": id,
                "endpoint_a": stream.key.ep_a, "endpoint_b": stream.key.ep_b, "conversation": report.as_ref()}),
            )?;
            continue;
        }
        let report = core
            .http_transactions(&id)
            .ok_or("Retained stream disappeared")?;
        if report.transactions.is_empty() {
            continue;
        }
        exchanges += report.transactions.len();
        event(
            output,
            &json!({"type": "http_conversation", "stream_id": id,
            "endpoint_a": stream.key.ep_a, "endpoint_b": stream.key.ep_b,
            "conversation": report.as_ref()}),
        )?;
    }
    let mut http3_exchanges = 0;
    let mut http3_pushes = 0;
    let mut http3_control_streams = 0;
    let mut http3_unclassified_streams = 0;
    for id in core.quic_scope.http3.connection_ids() {
        let report = core
            .quic_scope
            .http3
            .conversation(id)
            .ok_or("Retained QUIC connection disappeared")?;
        http3_exchanges += report.transactions.len();
        http3_pushes += report.pushes.len();
        http3_control_streams += report.control_streams.len();
        http3_unclassified_streams += report.unclassified_streams.len();
        event(
            output,
            &json!({"type": "http3_conversation", "connection_id": id, "conversation": report}),
        )?;
    }
    event(
        output,
        &json!({"type": "summary", "packets": packets,
        "analyzed": analyzed, "skipped": skipped, "truncated_frames": truncated_frames,
        "dns_capacity": dns_capacity,
        "frame_coverage_sha256_v1": frame_coverage_sha256_v1,
        "http_exchanges": exchanges + http2_exchanges + http3_exchanges,
        "http1_exchanges": exchanges, "http2_exchanges": http2_exchanges,
        "http3_exchanges": http3_exchanges, "quic_decode_errors": core.quic_scope.decode_errors,
        "http3_pushes": http3_pushes, "http3_control_streams": http3_control_streams,
        "http3_unclassified_streams": http3_unclassified_streams,
        "quic_last_decode_error": core.quic_scope.last_decode_error,
        "evicted_quic_connections": core.quic_scope.evicted_connections,
        "retained_streams": core.streams.len(), "evicted_streams": core.streams.evicted_streams(),
        "incidents": core.incidents.incidents.len(), "containment": "disabled",
        "graph_nodes": core.operator_graph.node_count(), "graph_edges": core.operator_graph.edge_count(),
        "transaction_scope": "retained_streams_only", "incident_history_limit": 256,
        "alerts_opened": replay.opened, "alert_snapshots": replay.snapshots}),
    )?;
    output.flush().map_err(|error| error.to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let mut input = None;
    let mut helper = None;
    let mut alerts_only = false;
    let mut allow_truncated = false;
    let mut vlan_policy = VlanPolicy::default();
    let mut replay = ReplayAlerts::default();
    let mut positional = false;
    while let Some(arg) = args.next() {
        if !positional && (arg == "--help" || arg == "-h") {
            println!(
                "Usage: packrat-analyze [--alerts-only] [--expect-alert RULE_ID=COUNT] [--expect-alert-frame RULE_ID=FRAME] [--allow-truncated] [--quic-decode-helper PROGRAM] [--single-tag-interface NAME] CAPTURE.pcap[ng]\nPassive offline NDJSON. No terminal, implicit user config, or containment.\nExpectations imply --alerts-only and exit nonzero on mismatches or skipped input. Truncated frames make expectations inconclusive unless --allow-truncated is set. TCP stream evictions make affected rule expectations inconclusive. --expect-alert counts newly grouped alerts; --expect-alert-frame labels their exact opening frames for a rule. Repeat the frame option for each expected frame.\n--single-tag-interface requires an exact PCAPNG interface name and may be repeated. Unnamed interfaces do not match.\nHTTP/1 and cleartext HTTP/2 cover retained TCP streams. Authenticated HTTP/3 requires an explicitly configured QUIC/QPACK helper. Limits and decoding failures are reported."
            );
            return Ok(());
        }
        if !positional && arg == "--" {
            positional = true;
            continue;
        }
        if !positional && arg == "--alerts-only" {
            alerts_only = true;
        } else if !positional && arg == "--allow-truncated" {
            allow_truncated = true;
        } else if !positional && arg == "--single-tag-interface" {
            let name = args.next().ok_or("--single-tag-interface requires a name")?;
            vlan_policy.add_single_tag_interface(name.to_str().ok_or("Interface name must be UTF-8")?)?;
        } else if !positional && arg == "--expect-alert" {
            let expectation = args.next().ok_or("Missing RULE_ID=COUNT after --expect-alert")?;
            replay.expect(expectation.to_str().ok_or("Alert expectations must be UTF-8")?)?;
            alerts_only = true;
        } else if !positional && arg == "--expect-alert-frame" {
            let expectation = args.next().ok_or("Missing RULE_ID=FRAME after --expect-alert-frame")?;
            replay.expect_frame(expectation.to_str().ok_or("Alert frame expectations must be UTF-8")?)?;
            alerts_only = true;
        } else if !positional && arg == "--quic-decode-helper" {
            if helper.is_some() {
                return Err("QUIC helper was specified twice".into());
            }
            helper = Some(std::path::PathBuf::from(
                args.next().ok_or("Missing QUIC decode helper program")?,
            ));
        } else if !positional && arg.to_string_lossy().starts_with('-') {
            return Err(format!("Unknown option: {}", arg.to_string_lossy()).into());
        } else if input.replace(arg).is_some() {
            return Err("Expected exactly one capture path".into());
        }
    }
    let input =
        input.ok_or("Usage: packrat-analyze [--quic-decode-helper PROGRAM] CAPTURE.pcap[ng]")?;
    let stdout = io::stdout();
    analyze(
        Path::new(&input),
        helper,
        alerts_only,
        allow_truncated,
        vlan_policy,
        replay,
        &mut BufWriter::new(stdout.lock()),
    )?;
    Ok(())
}
