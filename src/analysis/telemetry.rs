//! Small opt-in telemetry surface for daemon and collector integrations.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

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
    pub latency_p95_ms: f64,
    pub enriched_addresses: usize,
}

impl TelemetrySnapshot {
    pub fn openmetrics(&self) -> String {
        format!(
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
                "# TYPE packrat_latency_p95_milliseconds gauge\n",
                "packrat_latency_p95_milliseconds {:.3}\n",
                "# TYPE packrat_enriched_addresses gauge\n",
                "packrat_enriched_addresses {}\n",
                "# EOF\n"
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
            self.latency_p95_ms,
            self.enriched_addresses,
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct TelemetryHub {
    inner: Arc<RwLock<TelemetrySnapshot>>,
}

impl TelemetryHub {
    pub fn publish(&self, snapshot: TelemetrySnapshot) {
        if let Ok(mut current) = self.inner.write() {
            *current = snapshot;
        }
    }

    pub fn snapshot(&self) -> TelemetrySnapshot {
        self.inner.read().map(|snapshot| snapshot.clone()).unwrap_or_default()
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
        ("200 OK", "application/json", "{\"status\":\"ok\",\"service\":\"packrat\"}\n".to_string())
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
mod tests {
    use super::*;

    #[test]
    fn openmetrics_uses_packrat_namespace() {
        let metrics = TelemetrySnapshot { packets_total: 42, capturing: true, ..Default::default() }.openmetrics();
        assert!(metrics.contains("packrat_packets_observed_total 42"));
        assert!(metrics.contains("packrat_capture_active 1"));
        assert!(metrics.ends_with("# EOF\n"));
    }
}
