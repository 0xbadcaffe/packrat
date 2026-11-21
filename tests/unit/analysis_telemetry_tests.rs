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
    assert!(health()["pcap_buffer_drops"].is_null());

    hub.publish(TelemetrySnapshot {
        capturing: true,
        pcap_buffer_drops: Some(9),
        alert_save_failed: true,
        ..Default::default()
    });
    assert_eq!(health()["telemetry_fresh"], true);
    assert_eq!(health()["capture_active"], true);
    assert_eq!(health()["pcap_buffer_drops"], 9);
    assert_eq!(health()["alert_saving"], false);
    assert_eq!(health()["alert_save_failed"], true);

    hub.inner.write().unwrap().updated_at = Instant::now().checked_sub(Duration::from_secs(6));
    assert_eq!(health()["telemetry_fresh"], false);
}
