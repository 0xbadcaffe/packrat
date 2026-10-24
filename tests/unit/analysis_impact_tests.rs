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
    let id = store.open_or_update(
        IncidentSource::UserRule,
        "rule",
        "alert",
        Severity::Critical,
        &packet,
        std::iter::empty(),
    );
    let incident = store.active().unwrap();
    let event = EndpointEvidence {
        incident_id: id,
        target: packet.dst.clone(),
        source: "audit-log".into(),
        evidence_id: "event-42".into(),
        category: EndpointCategory::File,
        subject: "/srv/private/customer.csv".into(),
        action: "read".into(),
        successful: true,
    };
    let report = correlate(incident, &[event.clone()]);
    assert!(
        report
            .evidence
            .iter()
            .any(|entry| entry.subject == event.subject
                && entry.confidence == ImpactConfidence::Observed)
    );
    assert!(!report.compromise_confirmed);
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
