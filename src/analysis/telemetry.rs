//! Small opt-in telemetry surface for daemon and collector integrations.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::timeout;

const MAX_TELEMETRY_CONNECTIONS: usize = 16;
const TELEMETRY_DEADLINE: Duration = Duration::from_secs(2);
const MAX_REQUEST_BYTES: usize = 2048;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct CaptureQueueTelemetry {
    pub depth: usize,
    pub capacity: usize,
    pub dispatch_waiting: bool,
    pub analysis_packets_pending: usize,
}

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
    pub capture_run_id: Option<u64>,
    pub capture_interface: Option<String>,
    pub capture_link_type: Option<u32>,
    pub capture_id: Option<Arc<str>>,
    pub alert_session_id: Option<Arc<str>>,
    pub capture_queue: CaptureQueueTelemetry,
    pub pcap_buffer_drops: Option<u32>,
    pub capture_truncated_frames: Option<u64>,
    pub alert_saving: bool,
    pub alert_save_failed: bool,
    pub archive_enabled: bool,
    pub archive_paused: bool,
    pub archive_pause_reason: Option<&'static str>,
    pub archive_alert_evidence_only: bool,
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
        if let Some(truncated) = self.capture_truncated_frames {
            metrics.push_str(&format!(
                "# TYPE packrat_capture_truncated_frames_total counter\npackrat_capture_truncated_frames_total {truncated}\n"
            ));
        }
        for (name, value) in [
            ("capture_queue_depth", self.capture_queue.depth),
            ("capture_queue_capacity", self.capture_queue.capacity),
            ("capture_dispatch_waiting", usize::from(self.capture_queue.dispatch_waiting)),
            ("analysis_packets_pending", self.capture_queue.analysis_packets_pending),
        ] {
            metrics.push_str(&format!("# TYPE packrat_{name} gauge\npackrat_{name} {value}\n"));
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
    pub(crate) fn publish_capture_queue(&self, queue: CaptureQueueTelemetry) {
        if let Ok(mut state) = self.inner.write() {
            state.snapshot.capture_queue = queue;
        }
    }

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
            "packets_total": snapshot.packets_total,
            "capture_run_id": snapshot.capture_run_id.map(|id| format!("{id:016x}")),
            "capture_interface": snapshot.capture_interface.as_deref(),
            "capture_link_type": snapshot.capture_link_type,
            "capture_link_decodable": snapshot.capture_link_type.map(crate::net::parser::supports_capture_link_type),
            "capture_id": snapshot.capture_id.as_deref(),
            "alert_session_id": snapshot.alert_session_id.as_deref(),
            "capture_queue": snapshot.capture_queue,
            "pcap_buffer_drops": snapshot.pcap_buffer_drops,
            "capture_truncated_frames": snapshot.capture_truncated_frames,
            "alert_saving": snapshot.alert_saving,
            "alert_save_failed": snapshot.alert_save_failed,
            "archive_enabled": snapshot.archive_enabled,
            "archive_paused": snapshot.archive_paused,
            "archive_pause_reason": snapshot.archive_pause_reason,
            "archive_alert_evidence_only": snapshot.archive_alert_evidence_only,
        });
        format!("{body}\n")
    }
}

pub async fn bind(address: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(address).await
}

pub async fn serve(listener: TcpListener, hub: TelemetryHub) {
    serve_with_limits(listener, hub, MAX_TELEMETRY_CONNECTIONS, TELEMETRY_DEADLINE).await;
}

async fn serve_with_limits(
    listener: TcpListener,
    hub: TelemetryHub,
    limit: usize,
    deadline: Duration,
) {
    let mut active = JoinSet::new();
    loop {
        tokio::select! {
            _ = active.join_next(), if !active.is_empty() => {}
            accepted = listener.accept(), if active.len() < limit => {
                let Ok((stream, _peer)) = accepted else { break };
                let hub = hub.clone();
                active.spawn(async move {
                    let _ = timeout(deadline, serve_connection(stream, hub)).await;
                });
            }
        }
    }
}

async fn serve_connection(mut stream: TcpStream, hub: TelemetryHub) -> std::io::Result<()> {
    let mut request = [0_u8; MAX_REQUEST_BYTES];
    let mut used = 0;
    let route = loop {
        let size = stream.read(&mut request[used..]).await?;
        if size == 0 {
            return Ok(());
        }
        let new_end = used + size;
        if request[used.saturating_sub(3)..new_end].windows(4).any(|w| w == b"\r\n\r\n") {
            break request_line(&request[..new_end]);
        }
        used = new_end;
        if used == request.len() {
            break Err("431 Request Header Fields Too Large");
        }
    };
    let (status, content_type, body) = match route {
        Ok(("GET", "/metrics")) => (
            "200 OK",
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
            hub.snapshot().openmetrics(),
        ),
        Ok(("GET", "/health")) => ("200 OK", "application/json", hub.health()),
        Ok(_) => ("404 Not Found", "text/plain; charset=utf-8", "not found\n".into()),
        Err(status) => (status, "text/plain; charset=utf-8", format!("{status}\n")),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

fn request_line(request: &[u8]) -> Result<(&str, &str), &'static str> {
    const BAD_REQUEST: &str = "400 Bad Request";
    let end = request.windows(2).position(|w| w == b"\r\n").ok_or(BAD_REQUEST)?;
    let mut fields = std::str::from_utf8(&request[..end]).map_err(|_| BAD_REQUEST)?.split(' ');
    match (fields.next(), fields.next(), fields.next(), fields.next()) {
        (Some(method), Some(path), Some("HTTP/1.0" | "HTTP/1.1"), None)
            if !method.is_empty() && path.starts_with('/') => Ok((method, path)),
        _ => Err(BAD_REQUEST),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/analysis_telemetry_tests.rs"]
mod tests;
