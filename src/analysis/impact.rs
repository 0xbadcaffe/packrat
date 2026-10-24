//! Evidence-based impact assessment. Detection alone never proves compromise.

use crate::analysis::incident::Incident;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ImpactConfidence {
    Observed,
    Suspected,
    Unknown,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImpactEvidence {
    pub category: String,
    pub subject: String,
    pub confidence: ImpactConfidence,
    pub explanation: String,
    pub packet_numbers: Vec<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImpactReport {
    pub target: String,
    pub compromise_confirmed: bool,
    pub evidence: Vec<ImpactEvidence>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointEvidence {
    pub incident_id: u64,
    pub target: String,
    pub source: String,
    pub evidence_id: String,
    pub category: EndpointCategory,
    pub subject: String,
    pub action: String,
    pub successful: bool,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointCategory {
    File,
    Data,
    Capability,
}

pub fn correlate(incident: &Incident, events: &[EndpointEvidence]) -> ImpactReport {
    let mut report = assess(incident);
    for event in events
        .iter()
        .filter(|event| event.incident_id == incident.id && event.target == incident.target)
    {
        if event.source.trim().is_empty()
            || event.evidence_id.trim().is_empty()
            || event.subject.trim().is_empty()
        {
            continue;
        }
        let category = match event.category {
            EndpointCategory::File => "files",
            EndpointCategory::Data => "data",
            EndpointCategory::Capability => "capabilities",
        };
        if event.successful {
            report.evidence.retain(|entry| {
                !(entry.category == category && entry.confidence == ImpactConfidence::Unknown)
            });
        }
        report.evidence.push(ImpactEvidence {
            category: category.into(),
            subject: event.subject.clone(),
            confidence: if event.successful { ImpactConfidence::Observed } else { ImpactConfidence::Suspected },
            explanation: format!("Endpoint report {} / {}: {} (successful={}). Reporter attribution is not independent verification of compromise.",
                event.source, event.evidence_id, event.action, event.successful),
            packet_numbers: Vec::new(),
        });
    }
    report
}

pub fn read_endpoint_evidence(path: &std::path::Path) -> Result<Vec<EndpointEvidence>, String> {
    use std::io::{BufRead, BufReader, Read};
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut events = Vec::new();
    let reader = BufReader::new(file.take(8 * 1024 * 1024 + 1));
    let mut total = 0usize;
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|error| error.to_string())?;
        total += line.len() + 1;
        if total > 8 * 1024 * 1024 || events.len() >= 10_000 {
            return Err("Endpoint evidence exceeds import limits".into());
        }
        if line.trim().is_empty() {
            continue;
        }
        let event = serde_json::from_str(&line)
            .map_err(|error| format!("Endpoint evidence line {}: {error}", index + 1))?;
        events.push(event);
    }
    Ok(events)
}

pub fn assess(incident: &Incident) -> ImpactReport {
    let mut report = ImpactReport {
        target: incident.target.clone(),
        compromise_confirmed: false,
        evidence: Vec::new(),
        limitations: vec![
            "A detection indicates suspicious activity; it does not establish successful exploitation.".into(),
            "Packet evidence cannot establish local file modification, execution, or acquired permissions without endpoint evidence.".into(),
            "Encrypted, missing, truncated, or unretained traffic limits the assessment.".into(),
        ],
    };
    for packet in &incident.packet_history {
        if packet.src != incident.target && packet.dst != incident.target {
            continue;
        }
        let direction = if packet.src == incident.target {
            "outbound"
        } else {
            "inbound"
        };
        let service = format!(
            "{} {}:{} -> {}:{}",
            packet.protocol,
            packet.src,
            packet
                .src_port
                .map(|port| port.to_string())
                .unwrap_or_else(|| "?".into()),
            packet.dst,
            packet
                .dst_port
                .map(|port| port.to_string())
                .unwrap_or_else(|| "?".into())
        );
        if let Some(existing) = report
            .evidence
            .iter_mut()
            .find(|entry| entry.subject == service)
        {
            if existing.packet_numbers.len() < 32 && !existing.packet_numbers.contains(&packet.no) {
                existing.packet_numbers.push(packet.no);
            }
        } else if report.evidence.len() < 128 {
            report.evidence.push(ImpactEvidence {
                category: "network_activity".into(),
                subject: service,
                confidence: ImpactConfidence::Observed,
                explanation: format!("Retained {direction} traffic involving the affected host; transfer purpose and exploitation success are unconfirmed."),
                packet_numbers: vec![packet.no],
            });
        }
    }
    for (category, explanation) in [
        (
            "files",
            "Affected local files are unknown. Collect file-access and file-integrity events from the target.",
        ),
        (
            "data",
            "Compromised data is unknown. Correlate reconstructed application transactions with endpoint and application audit logs.",
        ),
        (
            "capabilities",
            "Acquired system capabilities are unknown. Collect process execution, identity, privilege, and persistence events.",
        ),
    ] {
        report.evidence.push(ImpactEvidence {
            category: category.into(),
            subject: "Not established".into(),
            confidence: ImpactConfidence::Unknown,
            explanation: explanation.into(),
            packet_numbers: Vec::new(),
        });
    }
    report
}

#[cfg(test)]
mod tests {
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
}
