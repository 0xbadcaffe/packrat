//! Scoped, read-only export of the packet evidence behind an alert snapshot.

use anyhow::{Context, Result, anyhow, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use crate::analysis::alert_center::{AlertItem, MAX_ALERT_PACKET_REFS};
use crate::export::pcapng::PcapNgWriter;
use crate::storage::packet_archive::{PacketArchive, valid_capture_id};
use super::alert_history::{AlertLogs, ReverseAlertLines};
use super::alert_jsonl::ExistingAlertRecord;

mod verify;
pub use verify::{VerifiedEvidence, verify_alert_evidence};

const MANIFEST: &str = "manifest.json";
const PCAP: &str = "evidence.pcapng";

#[derive(Serialize)]
pub struct EvidenceExportSummary {
    pub recovered_frames: usize,
    pub missing_frames: usize,
}

#[derive(Serialize)]
pub struct EvidenceAvailability {
    pub session_id: String,
    pub capture_id: String,
    pub alert_id: u64,
    pub evidence_frame_set_sha256: String,
    pub frames: Vec<FrameAvailability>,
}

#[derive(Serialize)]
pub struct FrameAvailability {
    pub frame_number: u64,
    pub status: FrameStatus,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameStatus {
    Complete,
    Truncated,
    LengthUnknown,
    Missing,
    Unreadable,
}

#[derive(Serialize)]
struct ExportedCapture {
    file: &'static str,
    sha256: String,
    // The nth item identifies frame n+1 in the exported PCAPNG.
    source_frame_numbers: Vec<u64>,
}

#[derive(Serialize)]
struct EvidenceManifest<'a> {
    schema_version: u8,
    record_type: &'static str,
    session_id: &'a str,
    capture_id: &'a str,
    alert: &'a AlertItem,
    capture: Option<ExportedCapture>,
    missing_frame_numbers: Vec<u64>,
}

pub fn export_alert_evidence(
    archive: &mut PacketArchive,
    log: &Path,
    session_id: &str,
    alert_id: u64,
    output: &Path,
) -> Result<EvidenceExportSummary> {
    export_scoped_alert_evidence(archive, log, session_id, alert_id, None, output)
}

pub fn export_scoped_alert_evidence(
    archive: &mut PacketArchive,
    log: &Path,
    session_id: &str,
    alert_id: u64,
    capture_filter: Option<&str>,
    output: &Path,
) -> Result<EvidenceExportSummary> {
    export_alert_evidence_across_logs(
        archive, AlertLogs::new(log, &[])?, session_id, alert_id, capture_filter, output,
    )
}

pub fn export_alert_evidence_across_logs(
    archive: &mut PacketArchive,
    logs: AlertLogs<'_>,
    session_id: &str,
    alert_id: u64,
    capture_filter: Option<&str>,
    output: &Path,
) -> Result<EvidenceExportSummary> {
    let alert = latest_alert_in_logs(logs, session_id, alert_id, capture_filter)?;
    let (capture_id, frames) = scoped_frames(&alert)?;

    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(output).context("Create new evidence directory")?;
    let result = export_into(archive, output, session_id, capture_id, &alert, frames);
    if result.is_err() {
        let _ = std::fs::remove_file(output.join(MANIFEST));
        let _ = std::fs::remove_file(output.join(PCAP));
        let _ = std::fs::remove_dir(output);
    }
    result
}

pub fn alert_evidence_availability(
    archive: &mut PacketArchive,
    log: &Path,
    session_id: &str,
    alert_id: u64,
    capture_filter: Option<&str>,
) -> Result<EvidenceAvailability> {
    alert_evidence_across_logs(
        archive, AlertLogs::new(log, &[])?, session_id, alert_id, capture_filter,
    )
}

pub fn alert_evidence_across_logs(
    archive: &mut PacketArchive,
    logs: AlertLogs<'_>,
    session_id: &str,
    alert_id: u64,
    capture_filter: Option<&str>,
) -> Result<EvidenceAvailability> {
    let alert = latest_alert_in_logs(logs, session_id, alert_id, capture_filter)?;
    let (capture_id, frames) = scoped_frames(&alert)?;
    let evidence_frame_set_sha256 = evidence_frame_set_sha256(&frames);
    let frames = frames.into_iter().map(|frame_number| {
        let status = match archive.packet_for_capture(capture_id, frame_number) {
            Ok(Some(packet)) => match packet.capture {
                Some(metadata) if metadata.captured_length as usize != packet.bytes.len()
                    || metadata.wire_length < metadata.captured_length => FrameStatus::Unreadable,
                Some(metadata) if metadata.truncated() => FrameStatus::Truncated,
                Some(_) => FrameStatus::Complete,
                None => FrameStatus::LengthUnknown,
            },
            Ok(None) => FrameStatus::Missing,
            Err(_) => FrameStatus::Unreadable,
        };
        FrameAvailability { frame_number, status }
    }).collect();
    Ok(EvidenceAvailability {
        session_id: session_id.to_owned(),
        capture_id: capture_id.to_owned(),
        alert_id,
        evidence_frame_set_sha256,
        frames,
    })
}

pub(super) fn evidence_frame_set_sha256(sorted_unique_frames: &[u64]) -> String {
    let mut digest = Sha256::new();
    for frame in sorted_unique_frames {
        digest.update(frame.to_be_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn scoped_frames(alert: &AlertItem) -> Result<(&str, Vec<u64>)> {
    ensure!(alert.packet_refs.len() <= MAX_ALERT_PACKET_REFS, "Alert packet reference limit exceeded");
    let capture_id = alert.capture_id.as_deref().ok_or_else(|| {
        anyhow!("Alert has no capture ID; archive lookup would be ambiguous")
    })?;
    ensure!(valid_capture_id(capture_id), "Invalid archive capture ID");
    let frames = alert.evidence_frame_numbers();
    ensure!(!frames.is_empty(), "Alert does not reference any frames");

    Ok((capture_id, frames))
}

fn export_into(
    archive: &mut PacketArchive,
    output: &Path,
    session_id: &str,
    capture_id: &str,
    alert: &AlertItem,
    frames: Vec<u64>,
) -> Result<EvidenceExportSummary> {
    let pcap_path = output.join(PCAP);
    let mut writer = None;
    let mut recovered = Vec::new();
    let mut missing = Vec::new();
    for number in frames {
        let Some(packet) = archive.packet_for_capture(capture_id, number).map_err(anyhow::Error::msg)? else {
            missing.push(number);
            continue;
        };
        if writer.is_none() {
            writer = Some(PcapNgWriter::create(&pcap_path)?);
        }
        if let Some(writer) = &mut writer {
            writer.write_packet(&packet).with_context(|| format!("Export frame {number}"))?;
        }
        recovered.push(number);
    }
    let summary = EvidenceExportSummary {
        recovered_frames: recovered.len(),
        missing_frames: missing.len(),
    };
    let capture = if let Some(mut writer) = writer {
        writer.flush()?;
        drop(writer);
        Some(ExportedCapture { file: PCAP, sha256: file_hash(&pcap_path)?, source_frame_numbers: recovered })
    } else {
        None
    };
    let manifest = EvidenceManifest {
        schema_version: 1,
        record_type: "packrat_alert_evidence",
        session_id,
        capture_id,
        alert,
        capture,
        missing_frame_numbers: missing,
    };
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(output.join(MANIFEST))?;
    serde_json::to_writer_pretty(&mut file, &manifest)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(summary)
}

#[cfg(test)]
fn latest_alert(log: &Path, session_id: &str, alert_id: u64, capture_filter: Option<&str>) -> Result<AlertItem> {
    latest_alert_in_logs(AlertLogs::new(log, &[])?, session_id, alert_id, capture_filter)
}

fn latest_alert_in_logs(logs: AlertLogs<'_>, session_id: &str, alert_id: u64, capture_filter: Option<&str>) -> Result<AlertItem> {
    let mut line = Vec::new();
    let mut selected: Option<AlertItem> = None;
    for (path, file) in logs.open_newest()? {
        let mut reader = ReverseAlertLines::new(file)
            .with_context(|| format!("Stat alert log {}", path.display()))?;
        while reader.next(&mut line).with_context(|| format!("Read alert log {}", path.display()))? {
            let Some(row) = ExistingAlertRecord::decode(&line) else { continue };
            if row.session_id == session_id && row.alert.id == alert_id
                && capture_filter.is_none_or(|scope| row.alert.capture_id.as_deref() == Some(scope))
            {
                if capture_filter.is_some() {
                    return Ok(row.alert);
                }
                ensure!(
                    selected.as_ref().is_none_or(|item| item.capture_id == row.alert.capture_id),
                    "Alert ID is ambiguous across captures in the specified session; specify --capture-id"
                );
                selected.get_or_insert(row.alert);
            }
        }
    }
    selected.ok_or_else(|| anyhow!("No matching alert in the specified session"))
}

fn file_hash(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
#[path = "../../tests/unit/storage_alert_evidence_tests.rs"]
mod tests;
