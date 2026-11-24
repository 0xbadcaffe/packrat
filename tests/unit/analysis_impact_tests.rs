use super::*;
use crate::analysis::incident::{IncidentSource, IncidentStore};
use crate::model::evidence::Severity;
use crate::net::parser::parse_ethernet;

#[test]
fn exploit_signature_does_not_claim_files_or_privileges_were_compromised() {
    let mut packet = parse_ethernet(&[], 7, 1.0);
    packet.src = "192.0.2.1".into();
    packet.dst = "192.0.2.2".into();
    let mut incidents = IncidentStore::default();
    incidents.open_or_update(
        IncidentSource::IndustrySignature,
        "RCE",
        "root shell /etc/shadow",
        Severity::Critical,
        &packet,
        std::iter::empty(),
    );
    let report = assess(incidents.active().unwrap());
    assert!(!report.compromise_confirmed);
    assert_eq!(
        report
            .evidence
            .iter()
            .filter(|entry| entry.confidence == ImpactConfidence::Unknown)
            .count(),
        3
    );
    assert_eq!(report.evidence[0].packet_numbers, vec![7]);
}

#[test]
fn endpoint_evidence_requires_matching_incident_target_and_provenance() {
    let mut packet = parse_ethernet(&[], 1, 1.0);
    packet.src = "192.0.2.1".into();
    packet.dst = "192.0.2.2".into();
    let mut store = IncidentStore::default();
    let id = store.open_or_update_scoped(
        (IncidentSource::UserRule, Some("capture-a")),
        "rule",
        "alert",
        Severity::Critical,
        &packet,
        std::iter::empty(),
    );
    let incident = store.active().unwrap();
    let event = EndpointEvidence {
        incident_id: id,
        capture_id: Some("capture-a".into()),
        target: packet.dst.clone(),
        source: "audit-log".into(),
        evidence_id: "event-42".into(),
        category: EndpointCategory::File,
        subject: "/srv/private/customer.csv".into(),
        action: "read".into(),
        successful: true,
    };
    let report = correlate(incident, &[event.clone(), event.clone()]);
    assert!(
        report
            .evidence
            .iter()
            .any(|entry| entry.subject == event.subject
                && entry.confidence == ImpactConfidence::Observed)
    );
    assert!(!report.compromise_confirmed);
    assert_eq!(report.evidence.iter().filter(|entry| entry.subject == event.subject).count(), 1);
    let mut conflicting = event.clone();
    conflicting.successful = false;
    let report = correlate(incident, &[event.clone(), conflicting, event.clone()]);
    assert_eq!(report.conflicting_endpoint_report_ids, 1);
    assert!(!report.evidence.iter().any(|entry| entry.subject == event.subject));
    assert!(report.evidence.iter().any(|entry| entry.category == "files"
        && entry.confidence == ImpactConfidence::Unknown));
    assert_eq!(report.capture_id.as_deref(), Some("capture-a"));
    for capture_id in [None, Some("capture-b".into())] {
        let unrelated = EndpointEvidence { capture_id, ..event.clone() };
        assert!(!correlate(incident, &[unrelated]).evidence.iter()
            .any(|entry| entry.subject == event.subject));
    }
    let mut legacy = incident.clone();
    legacy.capture_id = None;
    assert!(!correlate(&legacy, &[event.clone()]).evidence.iter()
        .any(|entry| entry.subject == event.subject));
    let mut unrelated = event.clone();
    unrelated.target = "192.0.2.99".into();
    assert!(
        !correlate(incident, &[unrelated])
            .evidence
            .iter()
            .any(|entry| entry.subject == event.subject)
    );
    let mut failed = event;
    failed.successful = false;
    assert!(
        correlate(incident, &[failed])
            .evidence
            .iter()
            .any(|entry| entry.category == "files"
                && entry.confidence == ImpactConfidence::Unknown)
    );
}
