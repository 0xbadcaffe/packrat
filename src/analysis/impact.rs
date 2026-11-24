//! Evidence-based impact assessment. Detection alone never proves compromise.

use crate::analysis::incident::Incident;
use std::collections::{BTreeMap, HashSet};

const MAX_ENDPOINT_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENDPOINT_EVIDENCE_EVENTS: usize = 10_000;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_id: Option<String>,
    pub compromise_confirmed: bool,
    #[serde(default)]
    pub conflicting_endpoint_report_ids: usize,
    pub evidence: Vec<ImpactEvidence>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointEvidence {
    pub incident_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_id: Option<String>,
    pub target: String,
    pub source: String,
    pub evidence_id: String,
    pub category: EndpointCategory,
    pub subject: String,
    pub action: String,
    pub successful: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointCategory {
    File,
    Data,
    Capability,
}

pub fn correlate(incident: &Incident, events: &[EndpointEvidence]) -> ImpactReport {
    let mut report = assess(incident);
    let Some(capture_id) = report.capture_id.as_deref() else { return report; };
    let mut reports = BTreeMap::<_, Option<&EndpointEvidence>>::new();
    for event in events
        .iter()
        .filter(|event| event.capture_id.as_deref() == Some(capture_id)
            && event.incident_id == incident.id && event.target == incident.target)
    {
        if event.source.trim().is_empty()
            || event.evidence_id.trim().is_empty()
            || event.subject.trim().is_empty()
        {
            continue;
        }
        reports.entry((event.source.as_str(), event.evidence_id.as_str()))
            .and_modify(|prior| {
                if prior.is_some_and(|prior| prior != event) { *prior = None; }
            })
            .or_insert(Some(event));
    }
    for event in reports.into_values() {
        let Some(event) = event else {
            report.conflicting_endpoint_report_ids += 1;
            continue;
        };
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
    if report.conflicting_endpoint_report_ids > 0 {
        report.limitations.push("Conflicting endpoint reports with the same reporter and evidence ID were omitted.".into());
    }
    report
}

pub fn read_endpoint_evidence(path: &std::path::Path) -> Result<Vec<EndpointEvidence>, String> {
    use std::io::{BufRead, BufReader, Read};
    let (file, metadata) = crate::storage::regular_file::open(path, "Endpoint evidence is not a regular file")
        .map_err(|error| error.to_string())?;
    if metadata.len() > MAX_ENDPOINT_EVIDENCE_BYTES as u64 {
        return Err("Endpoint evidence exceeds import limits".into());
    }
    let mut events = Vec::new();
    let mut reader = BufReader::new(file.take(MAX_ENDPOINT_EVIDENCE_BYTES as u64 + 1));
    let mut total = 0usize;
    let mut line = String::new();
    let mut line_number = 0;
    loop {
        line.clear();
        let read = reader.read_line(&mut line).map_err(|error| error.to_string())?;
        if read == 0 { break; }
        line_number += 1;
        total += read;
        if total > MAX_ENDPOINT_EVIDENCE_BYTES {
            return Err("Endpoint evidence exceeds import limits".into());
        }
        if line.trim().is_empty() {
            continue;
        }
        if events.len() >= MAX_ENDPOINT_EVIDENCE_EVENTS {
            return Err("Endpoint evidence exceeds import limits".into());
        }
        let event = serde_json::from_str(&line)
            .map_err(|error| format!("Endpoint evidence line {line_number}: {error}"))?;
        events.push(event);
    }
    Ok(events)
}

pub(crate) fn validate_endpoint_evidence(events: &[EndpointEvidence]) -> Result<(), String> {
    if events.len() > MAX_ENDPOINT_EVIDENCE_EVENTS
        || serde_json::to_vec(events).map_err(|error| error.to_string())?.len() > MAX_ENDPOINT_EVIDENCE_BYTES
    {
        return Err("Endpoint evidence exceeds case limits".into());
    }
    Ok(())
}

pub(crate) fn merge_endpoint_evidence(
    saved: &mut Vec<EndpointEvidence>, imported: Vec<EndpointEvidence>,
) -> Result<(), String> {
    let prior = saved.len();
    let unique = {
        let mut seen: HashSet<_> = saved.iter().collect();
        imported.iter().map(|event| seen.insert(event)).collect::<Vec<_>>()
    };
    saved.extend(imported.into_iter().zip(unique).filter_map(|(event, keep)| keep.then_some(event)));
    if let Err(error) = validate_endpoint_evidence(saved) {
        saved.truncate(prior);
        return Err(error);
    }
    Ok(())
}

pub fn assess(incident: &Incident) -> ImpactReport {
    let mut report = ImpactReport {
        target: incident.target.clone(),
        capture_id: incident.capture_id.clone().filter(|id| crate::storage::packet_archive::valid_capture_id(id)),
        compromise_confirmed: false,
        conflicting_endpoint_report_ids: 0,
        evidence: Vec::new(),
        limitations: vec![
            "A detection indicates suspicious activity; it does not establish successful exploitation.".into(),
            "Packet evidence cannot establish local file modification, execution, or acquired permissions without endpoint evidence.".into(),
            "Encrypted, missing, truncated, or unretained traffic limits the assessment.".into(),
            "Endpoint reports require a matching capture ID, incident ID, and target. Unscoped reports do not establish impact.".into(),
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
#[path = "../../tests/unit/analysis_impact_tests.rs"]
mod tests;
