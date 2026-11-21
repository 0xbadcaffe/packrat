//! Read-only, bounded summaries of the latest snapshots in a saved alert log.

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{collections::VecDeque, fs::File, io::BufReader, path::Path};

use crate::analysis::alert_center::{AlertDisposition, MAX_ALERT_PACKET_REFS};
use crate::analysis::alert_provenance::EvidenceConfidence;
use super::alert_jsonl::{ExistingAlertRecord, next_alert_line};

pub const MAX_HISTORY_LIMIT: usize = 512;

#[derive(Serialize)]
pub struct AlertHistoryEntry {
    pub session_id: String,
    pub capture_id: Option<String>,
    pub alert_id: u64,
    pub title: String,
    pub severity: String,
    pub detail: String,
    pub disposition: AlertDisposition,
    pub first_seen: f64,
    pub last_seen: f64,
    pub hit_count: u64,
    pub evidence_frame_count: usize,
    pub rule_id: Option<String>,
    pub revision: Option<u16>,
    pub confidence: Option<EvidenceConfidence>,
    pub verify: Option<String>,
}

pub fn recent_alerts(
    log: &Path,
    session_filter: Option<&str>,
    capture_filter: Option<&str>,
    limit: usize,
) -> Result<Vec<AlertHistoryEntry>> {
    ensure!((1..=MAX_HISTORY_LIMIT).contains(&limit), "Alert history limit must be 1..={MAX_HISTORY_LIMIT}");
    let mut reader = BufReader::new(File::open(log).context("Open saved alert log")?);
    let mut line = Vec::new();
    let mut latest = VecDeque::<AlertHistoryEntry>::with_capacity(limit);
    while next_alert_line(&mut reader, &mut line).context("Read saved alert log")? {
        let Some(record) = ExistingAlertRecord::decode(&line) else { continue };
        let alert = record.alert;
        if record.session_id.is_empty() || record.session_id.len() > 128
            || alert.capture_id.as_ref().is_some_and(|id| id.is_empty() || id.len() > 128)
            || alert.packet_refs.len() > MAX_ALERT_PACKET_REFS
            || session_filter.is_some_and(|id| record.session_id != id)
            || capture_filter.is_some_and(|id| alert.capture_id.as_deref() != Some(id))
        {
            continue;
        }
        if let Some(old) = latest.iter().position(|entry| {
            entry.session_id == record.session_id && entry.capture_id == alert.capture_id
                && entry.alert_id == alert.id
        }) {
            latest.remove(old);
        } else if latest.len() == limit {
            latest.pop_front();
        }
        let evidence_frame_count = alert.evidence_frame_numbers().len();
        latest.push_back(AlertHistoryEntry {
            session_id: record.session_id,
            capture_id: alert.capture_id,
            alert_id: alert.id,
            title: limited(&alert.title, 160),
            severity: limited(&alert.severity, 16),
            detail: limited(&alert.detail, 512),
            disposition: alert.disposition,
            first_seen: alert.first_seen,
            last_seen: alert.last_seen,
            hit_count: alert.hit_count,
            evidence_frame_count,
            rule_id: alert.provenance.as_ref().map(|rule| limited(&rule.rule_id, 128)),
            revision: alert.provenance.as_ref().map(|rule| rule.revision),
            confidence: alert.provenance.as_ref().map(|rule| rule.confidence),
            verify: alert.provenance.as_ref().map(|rule| limited(&rule.verification_hint, 240)),
        });
    }
    // Deliver most recently appended snapshots first, including review updates.
    Ok(latest.into_iter().rev().collect())
}

fn limited(value: &str, chars: usize) -> String {
    value.chars().take(chars).collect()
}
