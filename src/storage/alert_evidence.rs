//! Scoped, read-only export of the packet evidence behind an alert snapshot.

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

use crate::analysis::alert_center::{AlertItem, MAX_ALERT_PACKET_REFS};
use crate::export::pcapng::PcapNgWriter;
use crate::storage::packet_archive::PacketArchive;

const MAX_ALERT_LINE: usize = 1_048_576;
const MANIFEST: &str = "manifest.json";
const PCAP: &str = "evidence.pcapng";

#[derive(Deserialize)]
struct AlertRow {
    schema_version: u8,
    record_type: String,
    session_id: String,
    alert: AlertItem,
}

#[derive(Serialize)]
pub struct EvidenceExportSummary {
    pub recovered_frames: usize,
    pub missing_frames: usize,
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
    let alert = latest_alert(log, session_id, alert_id)?;
    ensure!(alert.packet_refs.len() <= MAX_ALERT_PACKET_REFS, "Alert packet reference limit exceeded");
    let capture_id = alert.capture_id.as_deref().ok_or_else(|| {
        anyhow!("Alert has no capture ID; archive lookup would be ambiguous")
    })?;
    let frames = alert.evidence_frame_numbers();
    ensure!(!frames.is_empty(), "Alert does not reference any frames");

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

fn latest_alert(log: &Path, session_id: &str, alert_id: u64) -> Result<AlertItem> {
    let mut reader = BufReader::new(File::open(log).context("Open saved alert log")?);
    let mut line = Vec::new();
    let mut selected = None;
    loop {
        line.clear();
        let count = (&mut reader).take((MAX_ALERT_LINE + 1) as u64).read_until(b'\n', &mut line)?;
        if count == 0 {
            break;
        }
        if count > MAX_ALERT_LINE {
            if !line.ends_with(b"\n") {
                reader.skip_until(b'\n')?;
            }
            continue;
        }
        let Ok(row) = serde_json::from_slice::<AlertRow>(&line) else { continue };
        if row.schema_version == 1 && row.record_type == "alert"
            && row.session_id == session_id && row.alert.id == alert_id
        {
            selected = Some(row.alert);
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
