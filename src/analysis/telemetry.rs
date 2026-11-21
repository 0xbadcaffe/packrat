//! Small opt-in telemetry surface for daemon and collector integrations.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Clone, Default)]
pub struct TelemetrySnapshot {
    pub packets_total: u64,
    pub bytes_total: u64,
    pub visible_packets: usize,
    pub flows: usize,
    pub hosts: usize,
    pub security_findings: usize,
    pub rule_hits: usize,
    pub ioc_hits: usize,
    pub pending_incidents: usize,
    pub evidence_exports: usize,
    pub packets_per_second: u32,
    pub capturing: bool,
    pub pcap_buffer_drops: Option<u32>,
    pub alert_saving: bool,
    pub alert_save_failed: bool,
    pub archive_enabled: bool,
    pub archive_paused: bool,
    pub latency_p95_ms: f64,
    pub enriched_addresses: usize,
}

impl TelemetrySnapshot {
    pub fn openmetrics(&self) -> String {
        let mut metrics = format!(
            concat!(
                "# TYPE packrat_packets_observed_total counter\n",
                "packrat_packets_observed_total {}\n",
                "# TYPE packrat_bytes_observed_total counter\n",
                "packrat_bytes_observed_total {}\n",
                "# TYPE packrat_visible_packets gauge\n",
                "packrat_visible_packets {}\n",
                "# TYPE packrat_active_flows gauge\n",
                "packrat_active_flows {}\n",
                "# TYPE packrat_hosts_observed gauge\n",
                "packrat_hosts_observed {}\n",
                "# TYPE packrat_security_findings gauge\n",
                "packrat_security_findings {}\n",
                "# TYPE packrat_rule_hits gauge\n",
                "packrat_rule_hits {}\n",
                "# TYPE packrat_ioc_hits gauge\n",
                "packrat_ioc_hits {}\n",
                "# TYPE packrat_pending_incidents gauge\n",
                "packrat_pending_incidents {}\n",
                "# TYPE packrat_evidence_exports gauge\n",
                "packrat_evidence_exports {}\n",
                "# TYPE packrat_packets_per_second gauge\n",
                "packrat_packets_per_second {}\n",
                "# TYPE packrat_capture_active gauge\n",
                "packrat_capture_active {}\n",
                "# TYPE packrat_capture_pcap_stats_available gauge\n",
                "packrat_capture_pcap_stats_available {}\n",
                "# TYPE packrat_alert_saving gauge\n",
                "packrat_alert_saving {}\n",
                "# TYPE packrat_alert_save_failed gauge\n",
                "packrat_alert_save_failed {}\n",
                "# TYPE packrat_archive_enabled gauge\n",
                "packrat_archive_enabled {}\n",
                "# TYPE packrat_archive_paused gauge\n",
                "packrat_archive_paused {}\n",
                "# TYPE packrat_latency_p95_milliseconds gauge\n",
                "packrat_latency_p95_milliseconds {:.3}\n",
                "# TYPE packrat_enriched_addresses gauge\n",
                "packrat_enriched_addresses {}\n",
            ),
            self.packets_total,
            self.bytes_total,
            self.visible_packets,
            self.flows,
            self.hosts,
            self.security_findings,
            self.rule_hits,
            self.ioc_hits,
            self.pending_incidents,
            self.evidence_exports,
            self.packets_per_second,
            u8::from(self.capturing),
            u8::from(self.pcap_buffer_drops.is_some()),
            u8::from(self.alert_saving),
            u8::from(self.alert_save_failed),
            u8::from(self.archive_enabled),
            u8::from(self.archive_paused),
            self.latency_p95_ms,
            self.enriched_addresses,
        );
        if let Some(dropped) = self.pcap_buffer_drops {
            metrics.push_str(&format!(
                "# TYPE packrat_capture_pcap_buffer_drops gauge\npackrat_capture_pcap_buffer_drops {dropped}\n"
            ));
        }
        metrics.push_str("# EOF\n");
        metrics
    }
}

#[derive(Debug, Clone, Default)]
pub struct TelemetryHub {
    inner: Arc<RwLock<TelemetryState>>,
}

#[derive(Debug, Default)]
struct TelemetryState {
    snapshot: TelemetrySnapshot,
    updated_at: Option<Instant>,
}

impl TelemetryHub {
    pub fn publish(&self, snapshot: TelemetrySnapshot) {
        if let Ok(mut current) = self.inner.write() {
            *current = TelemetryState {
                snapshot,
                updated_at: Some(Instant::now()),
            };
        }
    }

    pub fn snapshot(&self) -> TelemetrySnapshot {
        self.inner.read().map(|state| state.snapshot.clone()).unwrap_or_default()
    }

    fn health(&self) -> String {
        let (snapshot, updated_at) = self
            .inner
            .read()
            .map(|state| (state.snapshot.clone(), state.updated_at))
            .unwrap_or_default();
        let age = updated_at.map(|time| time.elapsed());
        let body = serde_json::json!({
            "status": "ok",
            "service": "packrat",
            "telemetry_fresh": age.is_some_and(|age| age <= Duration::from_secs(5)),
            "capture_active": snapshot.capturing,
            "pcap_buffer_drops": snapshot.pcap_buffer_drops,
            "alert_saving": snapshot.alert_saving,
            "alert_save_failed": snapshot.alert_save_failed,
            "archive_enabled": snapshot.archive_enabled,
            "archive_paused": snapshot.archive_paused,
        });
        format!("{body}\n")
    }
}

pub async fn bind(address: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(address).await
}

pub async fn serve(listener: TcpListener, hub: TelemetryHub) {
    while let Ok((stream, _peer)) = listener.accept().await {
        let hub = hub.clone();
        tokio::spawn(async move {
            let _ = serve_connection(stream, hub).await;
        });
    }
}

async fn serve_connection(mut stream: TcpStream, hub: TelemetryHub) -> std::io::Result<()> {
    let mut request = [0_u8; 2048];
    let size = stream.read(&mut request).await?;
    let first_line = std::str::from_utf8(&request[..size])
        .ok()
        .and_then(|request| request.lines().next())
        .unwrap_or("");
    let (status, content_type, body) = if first_line.starts_with("GET /metrics ") {
        ("200 OK", "application/openmetrics-text; version=1.0.0; charset=utf-8", hub.snapshot().openmetrics())
    } else if first_line.starts_with("GET /health ") {
        ("200 OK", "application/json", hub.health())
    } else {
        ("404 Not Found", "text/plain; charset=utf-8", "not found\n".to_string())
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

#[cfg(test)]
#[path = "../../tests/unit/analysis_telemetry_tests.rs"]
mod tests;
