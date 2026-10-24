use super::*;

#[test]
fn openmetrics_uses_packrat_namespace() {
    let metrics = TelemetrySnapshot { packets_total: 42, capturing: true, ..Default::default() }.openmetrics();
    assert!(metrics.contains("packrat_packets_observed_total 42"));
    assert!(metrics.contains("packrat_capture_active 1"));
    assert!(metrics.ends_with("# EOF\n"));
}
