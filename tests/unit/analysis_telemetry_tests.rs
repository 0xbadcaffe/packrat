use super::*;

#[test]
fn openmetrics_uses_packrat_namespace() {
    let metrics = TelemetrySnapshot { packets_total: 42, capturing: true, ..Default::default() }.openmetrics();
    assert!(metrics.contains("packrat_packets_observed_total 42"));
    assert!(metrics.contains("packrat_capture_active 1"));
    assert!(metrics.ends_with("# EOF\n"));
}

#[test]
fn metrics_do_not_report_unknown_loss_as_zero() {
    let unknown = TelemetrySnapshot::default().openmetrics();
    assert!(unknown.contains("packrat_capture_pcap_stats_available 0"));
    assert!(!unknown.contains("packrat_capture_pcap_buffer_drops"));
    let known = TelemetrySnapshot {
        pcap_buffer_drops: Some(0),
        alert_saving: true,
        archive_enabled: true,
        archive_paused: true,
        ..Default::default()
    }.openmetrics();
    assert!(known.contains("packrat_capture_pcap_stats_available 1"));
    assert!(known.contains("packrat_capture_pcap_buffer_drops 0"));
    assert!(known.contains("packrat_alert_saving 1"));
    assert!(known.contains("packrat_archive_paused 1"));
}

#[test]
fn health_distinguishes_liveness_from_fresh_capture_and_persistence_status() {
    let hub = TelemetryHub::default();
    let health = || serde_json::from_str::<serde_json::Value>(&hub.health()).unwrap();
    assert_eq!(health()["status"], "ok");
    assert_eq!(health()["telemetry_fresh"], false);
    assert!(health()["capture_run_id"].is_null());
    assert!(health()["capture_interface"].is_null());
    assert!(health()["alert_session_id"].is_null());
    assert!(health()["pcap_buffer_drops"].is_null());

    hub.publish(TelemetrySnapshot {
        capturing: true,
        capture_run_id: Some(0xfedc_ba98_7654_3210),
        capture_interface: Some("wlan1".into()),
        capture_id: Some("0123456789abcdef0123456789abcdef".into()),
        alert_session_id: Some("1000000-42".into()),
        pcap_buffer_drops: Some(9),
        alert_save_failed: true,
        ..Default::default()
    });
    assert_eq!(health()["telemetry_fresh"], true);
    assert_eq!(health()["capture_active"], true);
    assert_eq!(health()["capture_run_id"], "fedcba9876543210");
    assert_eq!(health()["capture_interface"], "wlan1");
    assert_eq!(health()["capture_id"], "0123456789abcdef0123456789abcdef");
    assert_eq!(health()["alert_session_id"], "1000000-42");
    assert_eq!(health()["pcap_buffer_drops"], 9);
    assert_eq!(health()["alert_saving"], false);
    assert_eq!(health()["alert_save_failed"], true);

    hub.inner.write().unwrap().updated_at = Instant::now().checked_sub(Duration::from_secs(6));
    assert_eq!(health()["telemetry_fresh"], false);
}

#[test]
fn queue_pressure_does_not_claim_packet_loss_or_refresh_analysis_health() {
    let hub = TelemetryHub::default();
    hub.publish_capture_queue(CaptureQueueTelemetry {
        depth: 75, capacity: 100, dispatch_waiting: true, analysis_packets_pending: 8,
    });
    let health: serde_json::Value = serde_json::from_str(&hub.health()).unwrap();
    assert_eq!(health["telemetry_fresh"], false);
    assert!(health["pcap_buffer_drops"].is_null());
    assert_eq!(health["capture_queue"]["depth"], 75);
    let metrics = hub.snapshot().openmetrics();
    assert!(metrics.contains("packrat_capture_queue_depth 75\n"));
    assert!(metrics.contains("packrat_capture_dispatch_waiting 1\n"));
    assert!(metrics.contains("packrat_analysis_packets_pending 8\n"));
}

#[tokio::test]
async fn telemetry_waits_for_complete_headers_and_bounds_request_size() {
    let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve(listener, TelemetryHub::default()));
    let mut health = TcpStream::connect(address).await.unwrap();
    health.write_all(b"GET /hea").await.unwrap();
    assert!(timeout(Duration::from_millis(25), health.read_u8()).await.is_err());
    health.write_all(b"lth HTTP/1.1\r\nHost: localhost\r\n\r").await.unwrap();
    assert!(timeout(Duration::from_millis(25), health.read_u8()).await.is_err());
    health.write_all(b"\n").await.unwrap();
    let mut response = String::new();
    timeout(Duration::from_secs(1), health.read_to_string(&mut response)).await.unwrap().unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    let (_, body) = response.split_once("\r\n\r\n").unwrap();
    assert_eq!(serde_json::from_str::<serde_json::Value>(body).unwrap()["service"], "packrat");

    let mut client = TcpStream::connect(address).await.unwrap();
    let mut request = b"GET /health HTTP/1.1\r\nX-Filler: ".to_vec();
    request.resize(MAX_REQUEST_BYTES, b'x');
    client.write_all(&request).await.unwrap();
    response.clear();
    timeout(Duration::from_secs(1), client.read_to_string(&mut response)).await.unwrap().unwrap();
    assert!(response.starts_with("HTTP/1.1 431 "));
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn incomplete_telemetry_connection_expires_and_queued_request_is_served() {
    let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_with_limits(
        listener, TelemetryHub::default(), 1, Duration::from_millis(150),
    ));
    let mut incomplete = TcpStream::connect(address).await.unwrap();
    incomplete.write_all(b"GET /metrics HTTP/1.1\r\n").await.unwrap();
    let mut queued = TcpStream::connect(address).await.unwrap();
    queued.write_all(b"GET /metrics HTTP/1.0\r\n\r\n").await.unwrap();
    assert!(timeout(Duration::from_millis(25), queued.read_u8()).await.is_err());

    let mut response = String::new();
    timeout(Duration::from_secs(1), incomplete.read_to_string(&mut response)).await.unwrap().unwrap();
    assert!(response.is_empty());
    timeout(Duration::from_secs(1), queued.read_to_string(&mut response)).await.unwrap().unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("packrat_capture_active 0"));
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}
