use packrat_tui::{analysis::alert_center::AlertDisposition, engine::AnalysisCore};

use super::periodic_datagram;

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
