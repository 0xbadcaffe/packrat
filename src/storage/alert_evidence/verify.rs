use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};

use super::{AlertItem, FrameStatus, MANIFEST, MAX_ALERT_PACKET_REFS, PCAP, frame_status, is_zero, scoped_frames};
use crate::export::pcapng::PcapNgWriter;
use crate::storage::alert_history::{AlertLogs, ReverseAlertLines};
use crate::storage::alert_jsonl::ExistingAlertRecord;
use crate::storage::packet_archive::PacketArchive;

const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CAPTURE_BYTES: u64 = (MAX_ALERT_PACKET_REFS as u64 + 3) * 2 * 1024 * 1024;

#[derive(Deserialize)]
struct Manifest {
    schema_version: u8,
    record_type: String,
    session_id: String,
    capture_id: String,
    alert: AlertItem,
    capture: Option<Capture>,
    missing_frame_numbers: Vec<u64>,
    #[serde(default)]
    unreadable_frame_numbers: Vec<u64>,
    #[serde(default)]
    length_unknown_frame_numbers: Vec<u64>,
}

#[derive(Deserialize)]
struct Capture {
    file: String,
    sha256: String,
    source_frame_numbers: Vec<u64>,
}

#[derive(Serialize)]
pub struct VerifiedEvidence {
    pub session_id: String,
    pub capture_id: String,
    pub alert_id: u64,
    pub recovered_frames: usize,
    pub missing_frames: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub unreadable_frames: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub length_unknown_frames: usize,
    pub capture_sha256_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_snapshot_matches_log: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_frames_verified: Option<usize>,
}

pub fn verify_alert_evidence(directory: &Path) -> Result<VerifiedEvidence> {
    verify(directory, None, None)
}

/// Check bundle integrity and require the exported alert snapshot in the supplied logs.
pub fn verify_logged_alert_evidence(directory: &Path, logs: AlertLogs<'_>) -> Result<VerifiedEvidence> {
    verify(directory, Some(logs), None)
}

/// Require the exported stream to match the claimed frame IDs in a supplied read-only archive.
pub fn verify_archived_alert_evidence(directory: &Path, archive: &Path, logs: Option<AlertLogs<'_>>) -> Result<VerifiedEvidence> {
    verify(directory, logs, Some(archive))
}

fn verify(directory: &Path, logs: Option<AlertLogs<'_>>, archive: Option<&Path>) -> Result<VerifiedEvidence> {
    let (file, _) = open_regular(&directory.join(MANIFEST), MAX_MANIFEST_BYTES)?;
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_MANIFEST_BYTES, "Evidence manifest exceeds size limit");
    let manifest: Manifest = serde_json::from_slice(&bytes).context("Decode evidence manifest")?;
    ensure!(manifest.schema_version == 1 && manifest.record_type == "packrat_alert_evidence",
        "Unsupported evidence manifest");
    ensure!(!manifest.session_id.is_empty() && manifest.session_id.len() <= 128, "Invalid evidence session ID");
    let (scope, expected) = scoped_frames(&manifest.alert)?;
    ensure!(scope == manifest.capture_id, "Manifest and alert capture IDs do not match");

    let recovered = manifest.capture.as_ref().map_or(&[][..], |capture| capture.source_frame_numbers.as_slice());
    let missing = &manifest.missing_frame_numbers;
    ensure!(recovered.len() + missing.len() == expected.len()
        && strict_order(recovered) && strict_order(missing), "Invalid evidence frame mapping");
    let mut mapped: Vec<_> = recovered.iter().chain(missing).copied().collect();
    mapped.sort_unstable();
    ensure!(mapped == expected, "Evidence frame mapping does not match alert references");
    let unreadable = &manifest.unreadable_frame_numbers;
    let unknown = &manifest.length_unknown_frame_numbers;
    ensure!(strict_order(unreadable) && strict_order(unknown)
        && unreadable.len() + unknown.len() <= missing.len()
        && unreadable.iter().chain(unknown).all(|number| missing.binary_search(number).is_ok())
        && unreadable.iter().all(|number| unknown.binary_search(number).is_err()),
        "Invalid evidence frame omission reasons");

    let pcap = directory.join(PCAP);
    let verified_hash = if let Some(capture) = &manifest.capture {
        ensure!(capture.file == PCAP && !recovered.is_empty(), "Invalid evidence capture reference");
        ensure!(capture.sha256.len() == 64 && capture.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Invalid evidence capture SHA-256");
        verify_capture(&pcap, &capture.sha256, recovered.len())?;
        Some(true)
    } else {
        match std::fs::symlink_metadata(&pcap) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("Check for unexpected evidence capture"),
            Ok(_) => anyhow::bail!("Evidence capture exists but the manifest does not reference it"),
        }
        None
    };
    let alert_snapshot_matches_log = if let Some(logs) = logs {
        ensure!(contains_snapshot(logs, &manifest)?, "No matching evidence alert snapshot in the supplied logs");
        Some(true)
    } else {
        None
    };
    let archive_frames_verified = if let Some(archive) = archive {
        let capture = manifest.capture.as_ref()
            .context("Evidence bundle contains no packets to compare with the archive")?;
        verify_archive_capture(archive, scope, capture)?;
        Some(recovered.len())
    } else {
        None
    };
    Ok(VerifiedEvidence {
        session_id: manifest.session_id,
        capture_id: manifest.capture_id,
        alert_id: manifest.alert.id,
        recovered_frames: recovered.len(),
        missing_frames: missing.len(),
        unreadable_frames: unreadable.len(),
        length_unknown_frames: unknown.len(),
        capture_sha256_verified: verified_hash,
        alert_snapshot_matches_log,
        archive_frames_verified,
    })
}

fn verify_archive_capture(directory: &Path, scope: &str, capture: &Capture) -> Result<()> {
    let mut archive = PacketArchive::open_readonly(directory).map_err(anyhow::Error::msg)?;
    let mut hash = Sha256::new();
    {
        let mut writer = PcapNgWriter::new(&mut hash);
        for &frame in &capture.source_frame_numbers {
            let packet = archive.packet_for_capture(scope, frame).map_err(anyhow::Error::msg)
                .with_context(|| format!("Read archived frame {frame}"))?
                .with_context(|| format!("Archived frame {frame} is missing from the supplied capture scope"))?;
            ensure!(matches!(frame_status(&packet), FrameStatus::Complete | FrameStatus::Truncated),
                "Archived frame {frame} lacks usable capture metadata");
            writer.write_packet(&packet).with_context(|| format!("Encode archived frame {frame}"))?;
        }
    }
    let actual_hash = format!("{:x}", hash.finalize());
    ensure!(actual_hash.eq_ignore_ascii_case(&capture.sha256), "Evidence capture does not match the archived frames");
    Ok(())
}

fn contains_snapshot(logs: AlertLogs<'_>, manifest: &Manifest) -> Result<bool> {
    let mut line = Vec::new();
    for (path, file) in logs.open_newest()? {
        let mut reader = ReverseAlertLines::new(file)
            .with_context(|| format!("Stat alert log {}", path.display()))?;
        while reader.next(&mut line).with_context(|| format!("Read alert log {}", path.display()))? {
            if let Some(record) = ExistingAlertRecord::decode(&line)
                && record.session_id == manifest.session_id
                && record.alert == manifest.alert
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn strict_order(frames: &[u64]) -> bool {
    frames.windows(2).all(|pair| pair[0] < pair[1])
}

fn open_regular(path: &Path, max_bytes: u64) -> Result<(File, u64)> {
    let metadata = std::fs::symlink_metadata(path).with_context(|| format!("Read {}", path.display()))?;
    ensure!(metadata.is_file(), "Evidence input is not a regular file: {}", path.display());
    let file = File::open(path).with_context(|| format!("Open {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file() && metadata.len() <= max_bytes,
        "Evidence input exceeds size or file type limits: {}", path.display());
    Ok((file, metadata.len()))
}

fn verify_capture(path: &Path, expected_hash: &str, expected_frames: usize) -> Result<()> {
    let (file, length) = open_regular(path, MAX_CAPTURE_BYTES)?;
    let mut reader = HashedRead { input: file.take(MAX_CAPTURE_BYTES + 1), hash: Sha256::new(), bytes: 0 };
    let count = crate::capture::pcapng::stream(&mut reader, |packet| {
        if packet.no > expected_frames as u64 {
            return Err("Evidence capture contains more packets than its frame mapping".into());
        }
        Ok(())
    }).map_err(anyhow::Error::msg).context("Read evidence PCAPNG")?;
    ensure!(count == expected_frames as u64, "Evidence capture count does not match its frame mapping");
    ensure!(reader.bytes == length, "Evidence capture changed while it was read");
    let actual_hash = format!("{:x}", reader.hash.finalize());
    ensure!(actual_hash.eq_ignore_ascii_case(expected_hash), "Evidence capture SHA-256 mismatch");
    Ok(())
}

struct HashedRead<R> {
    input: R,
    hash: Sha256,
    bytes: u64,
}

impl<R: Read> Read for HashedRead<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.input.read(buffer)?;
        self.hash.update(&buffer[..count]);
        self.bytes += count as u64;
        Ok(count)
    }
}
