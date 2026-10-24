//! Offline, passive analysis adapter. Never initializes a terminal or containment.

use std::collections::VecDeque;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use packrat_tui::engine::{AnalysisCore, PacketDisposition};
use packrat_tui::pcap_replay::stream_pcap;
use serde::Serialize;
use serde_json::json;

fn event(output: &mut impl Write, value: &impl Serialize) -> Result<(), String> {
    serde_json::to_writer(&mut *output, value).map_err(|error| error.to_string())?;
    output.write_all(b"\n").map_err(|error| error.to_string())
}

fn analyze(
    path: &Path,
    helper: Option<std::path::PathBuf>,
    output: &mut impl Write,
) -> Result<(), String> {
    let mut core = AnalysisCore::default();
    core.quic_scope.decode_helper_path = helper;
    // Only recent packets are supplied as pre-incident context. Capture bytes
    // remain in the original file; the input is never loaded wholesale.
    let mut history = VecDeque::with_capacity(256);
    let mut analyzed = 0u64;
    let mut skipped = 0u64;
    let packets = stream_pcap(path, |packet| {
        let outcome = core.analyze_with_history(&packet, history.iter().cloned());
        if outcome.disposition != PacketDisposition::Analyzed {
            skipped += 1;
            event(
                output,
                &json!({"type": "skipped_packet", "packet": packet.no,
                "reason": outcome.disposition}),
            )?;
            return Ok(());
        }
        analyzed += 1;
        for notice in outcome.incidents {
            event(
                output,
                &json!({"type": "incident", "packet": packet.no, "notice": notice}),
            )?;
        }
        if history.len() == 256 {
            history.pop_front();
        }
        history.push_back(packet);
        Ok(())
    })?;
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
    for id in core.quic_scope.http3.connection_ids() {
        let report = core
            .quic_scope
            .http3
            .conversation(id)
            .ok_or("Retained QUIC connection disappeared")?;
        http3_exchanges += report.transactions.len();
        event(
            output,
            &json!({"type": "http3_conversation", "connection_id": id, "conversation": report}),
        )?;
    }
    event(
        output,
        &json!({"type": "summary", "packets": packets,
        "analyzed": analyzed, "skipped": skipped, "http_exchanges": exchanges + http2_exchanges + http3_exchanges,
        "http1_exchanges": exchanges, "http2_exchanges": http2_exchanges,
        "http3_exchanges": http3_exchanges, "quic_decode_errors": core.quic_scope.decode_errors,
        "quic_last_decode_error": core.quic_scope.last_decode_error,
        "evicted_quic_connections": core.quic_scope.evicted_connections,
        "retained_streams": core.streams.len(), "evicted_streams": core.streams.evicted_streams(),
        "incidents": core.incidents.incidents.len(), "containment": "disabled",
        "graph_nodes": core.operator_graph.node_count(), "graph_edges": core.operator_graph.edge_count(),
        "transaction_scope": "retained_streams_only", "incident_history_limit": 256}),
    )?;
    output.flush().map_err(|error| error.to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let mut input = None;
    let mut helper = None;
    let mut positional = false;
    while let Some(arg) = args.next() {
        if !positional && (arg == "--help" || arg == "-h") {
            println!(
                "Usage: packrat-analyze [--quic-decode-helper PROGRAM] CAPTURE.pcap[ng]\nPassive offline NDJSON. No terminal, implicit user config, or containment.\nHTTP/1 and cleartext HTTP/2 cover retained TCP streams. Authenticated HTTP/3 requires an explicitly configured QUIC/QPACK helper. Limits and decoding failures are reported."
            );
            return Ok(());
        }
        if !positional && arg == "--" {
            positional = true;
            continue;
        }
        if !positional && arg == "--quic-decode-helper" {
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
        &mut BufWriter::new(stdout.lock()),
    )?;
    Ok(())
}
