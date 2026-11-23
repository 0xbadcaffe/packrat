use packrat_tui::{analysis::alert_center::AlertDisposition, engine::AnalysisCore};

use super::periodic_datagram;

#[test]
fn reverse_traffic_does_not_hide_a_new_periodic_episode() {
    let mut core = AnalysisCore::default();
    let forward = |frame, time| periodic_datagram(frame, time, 120, 50000, false);
    for index in 0..7 {
        core.analyze(&forward(index + 1, index as f64 * 10.0));
    }
    let first = &core.alert_center.items[0];
    let (id, scope) = (first.id, first.capture_id.clone());
    assert!(core.alert_center.set_disposition(id, scope.as_deref(), AlertDisposition::Benign));

    for (frame, time) in [(8, 1_000.0), (9, 2_750.0), (10, 3_650.0)] {
        core.analyze(&periodic_datagram(frame, time, 100, 50000, true));
    }
    core.analyze(&forward(11, 3_670.0));
    core.analyze(&forward(12, 3_640.0)); // A late frame from before the new episode.
    for index in 0..6 {
        core.analyze(&forward(index + 13, 3_680.0 + index as f64 * 10.0));
    }
    let alerts = &core.alert_center.items;
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0].disposition, AlertDisposition::Benign);
    assert_eq!(alerts[0].packet_refs, [1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(alerts[1].disposition, AlertDisposition::New);
    assert_eq!(alerts[1].packet_refs, [11, 13, 14, 15, 16, 17, 18]);
}

#[test]
fn a_periodic_burst_after_idle_expiry_keeps_its_own_evidence_and_review_state() {
    let mut core = AnalysisCore::default();
    let make = |frame, time| periodic_datagram(frame, time, 120, 50000, false);
    for index in 0..7 {
        core.analyze(&make(index + 1, index as f64 * 10.0));
    }
    let first = &core.alert_center.items[0];
    let (first_id, scope) = (first.id, first.capture_id.clone());
    assert!(core.alert_center.set_disposition(first_id, scope.as_deref(), AlertDisposition::Benign));
    for index in 0..7 {
        // The first packet lands on the inclusive expiry boundary, so this is not a new alert.
        core.analyze(&make(index + 8, 3660.0 + index as f64 * 10.0));
    }
    assert_eq!(core.alert_center.items.len(), 1);
    for index in 0..6 {
        core.analyze(&make(index + 15, 7321.0 + index as f64 * 10.0));
    }
    assert_eq!(core.alert_center.items.len(), 1);
    core.analyze(&make(21, 7381.0));

    let alerts = &core.alert_center.items;
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0].id, first_id);
    assert_eq!(alerts[0].disposition, AlertDisposition::Benign);
    assert_eq!(alerts[0].packet_refs, (1..=7).collect::<Vec<_>>());
    assert_eq!(alerts[1].disposition, AlertDisposition::New);
    assert_eq!(alerts[1].packet_refs, (15..=21).collect::<Vec<_>>());
    assert_eq!(alerts[1].severity, "MEDIUM");
    assert_ne!(alerts[1].correlation_key, alerts[0].correlation_key);
    assert!(alerts[1].detail.contains("Timing alone does not establish command-and-control"));
}

#[test]
fn unrelated_same_direction_sizes_cannot_keep_a_periodic_episode_open() {
    let mut core = AnalysisCore::default();
    let periodic = |frame, time| periodic_datagram(frame, time, 120, 50000, false);
    for index in 0..7 {
        core.analyze(&periodic(index + 1, index as f64 * 10.0));
    }
    assert_eq!(core.alert_center.items.len(), 1);
    for (frame, time) in [(8, 1_000.0), (9, 2_750.0), (10, 3_650.0)] {
        core.analyze(&periodic_datagram(frame, time, 450, 50000, false));
    }
    assert_eq!(core.alert_center.items.len(), 1);
    for index in 0..7 {
        core.analyze(&periodic(index + 11, 3_661.0 + index as f64 * 10.0));
    }
    let alerts = &core.alert_center.items;
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[1].severity, "MEDIUM");
    assert_eq!(alerts[1].packet_refs, [11, 12, 13, 14, 15, 16, 17]);
}
