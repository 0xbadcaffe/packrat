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
    assert!(!unknown.contains("packrat_capture_truncated_frames_total"));
    assert!(!unknown.contains("packrat_capture_queue_full_packets_total"));
    let known = TelemetrySnapshot {
        pcap_buffer_drops: Some(0),
        capture_truncated_frames: Some(2),
        capture_queue_full_packets: Some(17),
        alert_saving: true,
        alert_save_failures: 2,
        alert_save_backlog_dropped: 3,
        archive_enabled: true,
        archive_paused: true,
        ..Default::default()
    }.openmetrics();
    assert!(known.contains("packrat_capture_pcap_stats_available 1"));
    assert!(known.contains("packrat_capture_pcap_buffer_drops 0"));
    assert!(known.contains("packrat_capture_truncated_frames_total 2"));
    assert!(known.contains("packrat_capture_queue_full_packets_total 17"));
    assert!(known.contains("packrat_alert_saving 1"));
    assert!(known.contains("packrat_alert_save_failures_total 2"));
    assert!(known.contains("packrat_alert_save_backlog_dropped_total 3"));
    assert!(known.contains("packrat_archive_paused 1"));
}

#[test]
fn flow_cache_evictions_are_separate_from_capture_loss_and_require_fresh_health() {
    let hub = TelemetryHub::default();
    let health = || serde_json::from_str::<serde_json::Value>(&hub.health()).unwrap();
    assert!(health()["flow_cache"].is_null());
    hub.publish(TelemetrySnapshot {
        flows: 8192,
        flow_summary_evictions: 42,
        pcap_buffer_drops: Some(0),
        ..Default::default()
    });
    assert_eq!(health()["flow_cache"], serde_json::json!({
        "retained_summaries":8192,"summary_evictions":42
    }));
    assert_eq!(health()["pcap_buffer_drops"], 0);
    let metrics = hub.snapshot().openmetrics();
    assert!(metrics.contains("packrat_active_flows 8192\n"));
    assert!(metrics.contains("packrat_flow_summary_evictions_total 42\n"));
    assert!(metrics.contains("packrat_capture_pcap_buffer_drops 0\n"));
    hub.inner.write().unwrap().updated_at = Instant::now().checked_sub(Duration::from_secs(6));
    assert!(health()["flow_cache"].is_null());
}

#[test]
fn tcp_stream_evictions_are_separate_from_flow_summaries_and_capture_loss() {
    let hub = TelemetryHub::default();
    let health = || serde_json::from_str::<serde_json::Value>(&hub.health()).unwrap();
    assert!(health()["tcp_stream_cache"].is_null());
    assert!(!hub.snapshot().openmetrics().contains("packrat_tcp_stream_evictions_total"));
    hub.publish(TelemetrySnapshot {
        tcp_stream_cache: Some(TcpStreamCacheTelemetry { retained_streams: 500, evicted_streams: 9 }),
        flow_summary_evictions: 3,
        pcap_buffer_drops: Some(0),
        ..Default::default()
    });
    assert_eq!(health()["tcp_stream_cache"], serde_json::json!({"retained_streams":500,"evicted_streams":9}));
    assert_eq!(health()["flow_cache"]["summary_evictions"], 3);
    assert_eq!(health()["pcap_buffer_drops"], 0);
    let metrics = hub.snapshot().openmetrics();
    assert!(metrics.contains("packrat_tcp_retained_streams 500\n"));
    assert!(metrics.contains("packrat_tcp_stream_evictions_total 9\n"));
    hub.inner.write().unwrap().updated_at = Instant::now().checked_sub(Duration::from_secs(6));
    assert!(health()["tcp_stream_cache"].is_null());
}

#[test]
fn dns_capacity_counters_are_separate_from_capture_loss_and_require_fresh_health() {
    use crate::analysis::dns_transactions::DnsCapacityStats;

    let hub = TelemetryHub::default();
    let health = || serde_json::from_str::<serde_json::Value>(&hub.health()).unwrap();
    assert!(health()["dns_capacity"].is_null());
    assert!(!hub.snapshot().openmetrics().contains("packrat_dns_capacity_declines_total"));
    hub.publish(TelemetrySnapshot {
        dns_capacity: Some(DnsCapacityStats {
            query_key_declines: 4, query_candidate_declines: 7,
            nxdomain_client_declines: 0, external_resolver_pair_declines: 2,
        }),
        pcap_buffer_drops: Some(0),
        ..Default::default()
    });
    assert_eq!(health()["dns_capacity"], serde_json::json!({
        "query_key_declines":4, "query_candidate_declines":7,
        "nxdomain_client_declines":0, "external_resolver_pair_declines":2,
    }));
    assert_eq!(health()["pcap_buffer_drops"], 0);
    let metrics = hub.snapshot().openmetrics();
    for line in [
        "packrat_dns_capacity_declines_total{table=\"query_key\"} 4\n",
        "packrat_dns_capacity_declines_total{table=\"query_candidate\"} 7\n",
        "packrat_dns_capacity_declines_total{table=\"nxdomain_client\"} 0\n",
        "packrat_dns_capacity_declines_total{table=\"external_resolver_pair\"} 2\n",
    ] {
        assert!(metrics.contains(line), "{line}");
    }
    hub.inner.write().unwrap().updated_at = Instant::now().checked_sub(Duration::from_secs(6));
    assert!(health()["dns_capacity"].is_null());
}

#[test]
fn health_distinguishes_liveness_from_fresh_capture_and_persistence_status() {
    let hub = TelemetryHub::default();
    let health = || serde_json::from_str::<serde_json::Value>(&hub.health()).unwrap();
    assert_eq!(health()["status"], "ok");
    assert_eq!(health()["telemetry_fresh"], false);
    assert!(health()["capture_run_id"].is_null());
    assert!(health()["capture_interface"].is_null());
    assert!(health()["capture_link_type"].is_null());
    assert!(health()["capture_link_decodable"].is_null());
    assert!(health()["alert_session_id"].is_null());
    assert!(health()["pcap_buffer_drops"].is_null());
    assert!(health()["capture_truncated_frames"].is_null());
    assert!(health()["archive_pause_reason"].is_null());
    assert!(health()["archive_usage"].is_null());
    assert!(health()["archive_evidence_rules"].is_null());

    hub.publish(TelemetrySnapshot {
        capturing: true,
        packets_total: 1042,
        capture_run_id: Some(0xfedc_ba98_7654_3210),
        capture_interface: Some("wlan1".into()),
        capture_link_type: Some(113),
        capture_id: Some("0123456789abcdef0123456789abcdef".into()),
        alert_session_id: Some("1000000-42".into()),
        pcap_buffer_drops: Some(9),
        capture_truncated_frames: Some(2),
        capture_queue_full_packets: Some(17),
        alert_save_failed: true,
        alert_save_failures: 1,
        archive_enabled: true,
        archive_paused: true,
        archive_alert_evidence_only: true,
        archive_evidence_rules: Some(vec!["tcp.payload_after_observed_reset".into()]),
        archive_pause_reason: Some("disk_reserve"),
        archive_usage: Some(crate::storage::packet_archive::ArchiveUsage {
            frames: 9, max_frames: 10, payload_bytes: 51, max_payload_bytes: 100,
        }),
        ..Default::default()
    });
    assert_eq!(health()["telemetry_fresh"], true);
    assert_eq!(health()["capture_active"], true);
    assert_eq!(health()["packets_total"], 1042);
    assert_eq!(health()["capture_run_id"], "fedcba9876543210");
    assert_eq!(health()["capture_interface"], "wlan1");
    assert_eq!(health()["capture_link_type"], 113);
    assert_eq!(health()["capture_link_decodable"], false);
    assert_eq!(health()["capture_id"], "0123456789abcdef0123456789abcdef");
    assert_eq!(health()["alert_session_id"], "1000000-42");
    assert_eq!(health()["pcap_buffer_drops"], 9);
    assert_eq!(health()["capture_truncated_frames"], 2);
    assert_eq!(health()["capture_queue_full_packets"], 17);
    assert_eq!(health()["alert_saving"], false);
    assert_eq!(health()["alert_save_failed"], true);
    assert_eq!(health()["alert_save_failures"], 1);
    assert_eq!(health()["archive_paused"], true);
    assert_eq!(health()["archive_pause_reason"], "disk_reserve");
    assert_eq!(health()["archive_usage"]["frames"], 9);
    assert_eq!(health()["archive_usage"]["max_payload_bytes"], 100);
    assert_eq!(health()["archive_evidence_rules"], serde_json::json!(["tcp.payload_after_observed_reset"]));

    hub.inner.write().unwrap().updated_at = Instant::now().checked_sub(Duration::from_secs(6));
    assert_eq!(health()["telemetry_fresh"], false);
}

#[test]
fn ethernet_capture_reports_a_supported_link_type() {
    let hub = TelemetryHub::default();
    hub.publish(TelemetrySnapshot { capture_link_type: Some(1), ..Default::default() });
    let body: serde_json::Value = serde_json::from_str(&hub.health()).unwrap();
    assert_eq!(body["capture_link_type"], 1);
    assert_eq!(body["capture_link_decodable"], true);
}

#[test]
fn queue_pressure_does_not_claim_packet_loss_or_refresh_analysis_health() {
    let hub = TelemetryHub::default();
    hub.publish_capture_health(None, CaptureQueueTelemetry {
        depth: 75, capacity: 100, dispatch_waiting: true, analysis_packets_pending: 8,
    }, CaptureCounters::default());
    let health: serde_json::Value = serde_json::from_str(&hub.health()).unwrap();
    assert_eq!(health["telemetry_fresh"], false);
    assert!(health["pcap_buffer_drops"].is_null());
    assert_eq!(health["capture_queue"]["depth"], 75);
    let metrics = hub.snapshot().openmetrics();
    assert!(metrics.contains("packrat_capture_queue_depth 75\n"));
    assert!(metrics.contains("packrat_capture_dispatch_waiting 1\n"));
    assert!(metrics.contains("packrat_analysis_packets_pending 8\n"));
}

#[test]
fn partial_capture_health_does_not_mix_capture_runs_or_extend_freshness() {
    let hub = TelemetryHub::default();
    hub.publish(TelemetrySnapshot { capture_run_id: Some(1), capture_queue_full_packets: Some(0), ..Default::default() });
    let old_time = Instant::now().checked_sub(Duration::from_secs(6));
    hub.inner.write().unwrap().updated_at = old_time;
    let queue = CaptureQueueTelemetry { depth: 60, ..Default::default() };
    let counters = CaptureCounters { pcap_buffer_drops: Some(4), truncated_frames: Some(3), queue_full_packets: Some(95) };
    hub.publish_capture_health(Some(2), queue, counters);
    assert_eq!(hub.snapshot().capture_queue_full_packets, Some(0));
    assert_eq!(hub.snapshot().capture_queue.depth, 0);

    hub.publish_capture_health(Some(1), queue, counters);
    let health: serde_json::Value = serde_json::from_str(&hub.health()).unwrap();
    assert_eq!(health["telemetry_fresh"], false);
    assert_eq!(health["pcap_buffer_drops"], 4);
    assert_eq!(health["capture_truncated_frames"], 3);
    assert_eq!(health["capture_queue_full_packets"], 95);
    assert_eq!(health["capture_queue"]["depth"], 60);
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
