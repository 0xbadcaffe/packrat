//! Read-only, bounded summaries of the latest snapshots in a saved alert log.

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{collections::HashSet, fs::{File, OpenOptions}, io::{Read, Seek, SeekFrom}, path::{Path, PathBuf}};

use crate::analysis::alert_center::{AlertDisposition, AlertFlow, MAX_ALERT_PACKET_REFS};
use crate::analysis::alert_provenance::EvidenceConfidence;
use super::alert_jsonl::{ExistingAlertRecord, MAX_ALERT_LINE};
use super::alert_evidence::evidence_frame_set_sha256;

pub const MAX_HISTORY_LIMIT: usize = 512;
pub const MAX_PREVIOUS_LOGS: usize = 8;

pub struct AlertLogs<'a> {
    active: &'a Path,
    previous: &'a [PathBuf],
}

impl<'a> AlertLogs<'a> {
    pub fn new(active: &'a Path, previous: &'a [PathBuf]) -> Result<Self> {
        ensure!(previous.len() <= MAX_PREVIOUS_LOGS, "Too many previous alert logs");
        Ok(Self { active, previous })
    }

    pub(super) fn open_newest(&self) -> Result<Vec<(&'a Path, File)>> {
        std::iter::once(self.active)
            .chain(self.previous.iter().rev().map(PathBuf::as_path))
            .map(|path| {
                open_regular_log(path).map(|file| (path, file))
                    .with_context(|| format!("Open alert log {}", path.display()))
            }).collect()
    }
}

fn open_regular_log(path: &Path) -> Result<File> {
    ensure!(path.metadata()?.is_file(), "Not a regular alert log");
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // The path might be replaced with a FIFO between metadata and open.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    ensure!(file.metadata()?.is_file(), "Not a regular alert log");
    Ok(file)
}

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
    pub evidence_frame_set_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<AlertFlow>,
    pub rule_id: Option<String>,
    pub revision: Option<u16>,
    pub confidence: Option<EvidenceConfidence>,
    pub verify: Option<String>,
    pub review_limitations: Vec<&'static str>,
}

#[derive(Default, Serialize)]
pub struct AlertHistoryIntegrity {
    pub invalid_records: u64,
    pub oversized_records: u64,
    pub stopped_at_limit: bool,
}

#[derive(Serialize)]
pub struct AlertHistoryReport {
    pub alerts: Vec<AlertHistoryEntry>,
    pub integrity: AlertHistoryIntegrity,
}

pub fn recent_alerts(
    log: &Path,
    session_filter: Option<&str>,
    capture_filter: Option<&str>,
    limit: usize,
) -> Result<Vec<AlertHistoryEntry>> {
    recent_alerts_across_logs(&[], log, session_filter, capture_filter, limit)
}

pub fn recent_alerts_across_logs(
    previous: &[PathBuf],
    active: &Path,
    session_filter: Option<&str>,
    capture_filter: Option<&str>,
    limit: usize,
) -> Result<Vec<AlertHistoryEntry>> {
    Ok(recent_alerts_report(previous, active, session_filter, capture_filter, limit)?.alerts)
}

pub fn recent_alerts_report(
    previous: &[PathBuf],
    active: &Path,
    session_filter: Option<&str>,
    capture_filter: Option<&str>,
    limit: usize,
) -> Result<AlertHistoryReport> {
    filtered_alerts_report(previous, active, session_filter, capture_filter, None, limit)
}

pub fn exact_alert_report(
    previous: &[PathBuf],
    active: &Path,
    session: &str,
    capture: &str,
    alert_id: u64,
) -> Result<AlertHistoryReport> {
    ensure!(alert_id != 0, "Alert ID must be positive");
    filtered_alerts_report(previous, active, Some(session), Some(capture), Some(alert_id), 1)
}

fn filtered_alerts_report(
    previous: &[PathBuf],
    active: &Path,
    session_filter: Option<&str>,
    capture_filter: Option<&str>,
    alert_id: Option<u64>,
    limit: usize,
) -> Result<AlertHistoryReport> {
    ensure!((1..=MAX_HISTORY_LIMIT).contains(&limit), "Alert history limit must be 1..={MAX_HISTORY_LIMIT}");
    let logs = AlertLogs::new(active, previous)?;
    let mut latest = Vec::with_capacity(limit);
    let mut integrity = AlertHistoryIntegrity::default();
    let mut seen = HashSet::with_capacity(limit);
    let mut line = Vec::new();
    for (path, file) in logs.open_newest()? {
        let mut reader = ReverseAlertLines::new(file)
            .with_context(|| format!("Stat alert log {}", path.display()))?;
        loop {
            let found = reader.next(&mut line)
                .with_context(|| format!("Read alert log {}", path.display()))?;
            integrity.oversized_records += std::mem::take(&mut reader.oversized_records);
            if !found {
                break;
            }
            let Some(record) = ExistingAlertRecord::decode(&line) else {
                integrity.invalid_records += 1;
                continue;
            };
            let alert = record.alert;
            if record.session_id.is_empty() || record.session_id.len() > 128
                || alert.capture_id.as_ref().is_some_and(|id| id.is_empty() || id.len() > 128)
                || alert.packet_refs.len() > MAX_ALERT_PACKET_REFS
            {
                integrity.invalid_records += 1;
                continue;
            }
            if session_filter.is_some_and(|id| record.session_id != id)
                || capture_filter.is_some_and(|id| alert.capture_id.as_deref() != Some(id))
                || alert_id.is_some_and(|id| alert.id != id)
                || !seen.insert((record.session_id.clone(), alert.capture_id.clone(), alert.id))
            {
                continue;
            }
            let evidence_frames = alert.evidence_frame_numbers();
            let evidence_frame_count = evidence_frames.len();
            let mut review_limitations = Vec::new();
            if alert.capture_id.is_none() {
                review_limitations.push("capture_scope_not_recorded");
            }
            if alert.provenance.is_none() {
                review_limitations.push("rule_provenance_not_recorded");
            }
            if evidence_frame_count == 0 {
                review_limitations.push("no_packet_references");
            }
            latest.push(AlertHistoryEntry {
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
                evidence_frame_set_sha256: evidence_frame_set_sha256(&evidence_frames),
                flow: alert.flow,
                rule_id: alert.provenance.as_ref().map(|rule| limited(&rule.rule_id, 128)),
                revision: alert.provenance.as_ref().map(|rule| rule.revision),
                confidence: alert.provenance.as_ref().map(|rule| rule.confidence),
                verify: alert.provenance.as_ref().map(|rule| limited(&rule.verification_hint, 240)),
                review_limitations,
            });
            if latest.len() == limit {
                integrity.stopped_at_limit = true;
                return Ok(AlertHistoryReport { alerts: latest, integrity });
            }
        }
    }
    Ok(AlertHistoryReport { alerts: latest, integrity })
}

const READ_CHUNK: usize = 64 * 1024;

pub(super) struct ReverseAlertLines {
    file: File,
    chunk: Vec<u8>,
    offset: u64,
    end: usize,
    terminated: bool,
    oversized_records: u64,
}

impl ReverseAlertLines {
    pub(super) fn new(file: File) -> std::io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Not a regular alert log"));
        }
        Ok(Self { file, chunk: vec![0; READ_CHUNK], offset: metadata.len(), end: 0,
            terminated: false, oversized_records: 0 })
    }

    pub(super) fn next(&mut self, line: &mut Vec<u8>) -> std::io::Result<bool> {
        line.clear();
        let mut oversized = false;
        loop {
            if self.end == 0 {
                if self.offset == 0 {
                    self.oversized_records += u64::from(oversized);
                    line.reverse();
                    return Ok(!oversized && !line.is_empty());
                }
                self.end = self.offset.min(READ_CHUNK as u64) as usize;
                self.offset -= self.end as u64;
                self.file.seek(SeekFrom::Start(self.offset))?;
                self.file.read_exact(&mut self.chunk[..self.end])?;
            }
            let newline = self.chunk[..self.end].iter().rposition(|&byte| byte == b'\n');
            let start = newline.map_or(0, |pos| pos + 1);
            let bytes = &self.chunk[start..self.end];
            if !oversized && line.len() + bytes.len() + usize::from(self.terminated) <= MAX_ALERT_LINE {
                line.extend(bytes.iter().rev().copied());
            } else {
                oversized = true;
            }
            self.end = newline.unwrap_or(0);
            if newline.is_some() {
                self.terminated = true;
                self.oversized_records += u64::from(oversized);
                if !oversized && !line.is_empty() {
                    line.reverse();
                    return Ok(true);
                }
                oversized = false;
                line.clear();
            }
        }
    }
}

fn limited(value: &str, chars: usize) -> String {
    value.chars().take(chars).collect()
}
