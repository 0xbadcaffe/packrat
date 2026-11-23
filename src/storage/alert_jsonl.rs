//! Append-only, versioned JSONL export of Alert Center findings.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use crate::analysis::alert_center::{AlertItem, CREDENTIAL_ALERT_DETAIL};

pub(super) const MAX_ALERT_LINE: usize = 1_048_576;
const MAX_SAVED_ALERTS: usize = 4096;
const MAX_EXPORTED_DESCRIPTION: usize = 32 * 1024;
const MAX_EXPORTED_LABEL: usize = 4 * 1024;

type SnapshotKey = (u64, Option<[u8; 32]>);
type SnapshotDigest = [u8; 32];

enum LogSession {
    Fresh,
    Resume,
}

pub struct AlertJsonlWriter {
    path: PathBuf,
    session_id: String,
    latest_snapshots: BTreeMap<SnapshotKey, SnapshotDigest>,
    needs_separator: bool,
    writer: File,
}

#[derive(serde::Serialize)]
struct AlertRecord<'a> {
    schema_version: u8,
    record_type: &'static str,
    session_id: &'a str,
    alert: &'a AlertItem,
}

#[derive(serde::Deserialize)]
pub(super) struct ExistingAlertRecord {
    schema_version: u8,
    record_type: String,
    pub(super) session_id: String,
    pub(super) alert: AlertItem,
}

impl ExistingAlertRecord {
    pub(super) fn decode(line: &[u8]) -> Option<Self> {
        let record = serde_json::from_slice::<Self>(line).ok()?;
        (record.schema_version == 1 && record.record_type == "alert").then_some(record)
    }
}

pub(super) fn next_alert_line(
    reader: &mut impl BufRead,
    line: &mut Vec<u8>,
) -> std::io::Result<bool> {
    loop {
        line.clear();
        let count = (&mut *reader)
            .take((MAX_ALERT_LINE + 1) as u64)
            .read_until(b'\n', line)?;
        if count <= MAX_ALERT_LINE {
            return Ok(count != 0);
        }
        if !line.ends_with(b"\n") {
            reader.skip_until(b'\n')?;
        }
    }
}

fn snapshot_key(alert: &AlertItem) -> SnapshotKey {
    (
        alert.id,
        alert.capture_id.as_ref().map(|id| Sha256::digest(id.as_bytes()).into()),
    )
}

fn clip_exported_text(text: &mut String, max_bytes: usize) {
    const MARKER: &str = "[Truncated] ";
    if text.len() > max_bytes {
        let mut end = max_bytes - MARKER.len();
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.insert_str(0, MARKER);
    }
}

fn encode_alert_record(session_id: &str, alert: &AlertItem) -> Result<Vec<u8>, String> {
    let redact = alert.source == "CREDENTIAL" && alert.detail != CREDENTIAL_ALERT_DETAIL;
    let bounded = (redact || alert.detail.len() > MAX_EXPORTED_DESCRIPTION
        || alert.title.len() > MAX_EXPORTED_LABEL
        || alert.recommendation.as_ref().is_some_and(|text| text.len() > MAX_EXPORTED_LABEL)).then(|| {
        let mut copy = alert.clone();
        if redact {
            copy.detail = CREDENTIAL_ALERT_DETAIL.into();
        } else {
            clip_exported_text(&mut copy.detail, MAX_EXPORTED_DESCRIPTION);
        }
        clip_exported_text(&mut copy.title, MAX_EXPORTED_LABEL);
        if let Some(text) = &mut copy.recommendation {
            clip_exported_text(text, MAX_EXPORTED_LABEL);
        }
        copy
    });
    serde_json::to_vec(&AlertRecord {
        schema_version: 1,
        record_type: "alert",
        session_id,
        alert: bounded.as_ref().unwrap_or(alert),
    })
    .map_err(|error| format!("Serialize alert JSONL record: {error}"))
}

fn remember(
    snapshots: &mut BTreeMap<SnapshotKey, SnapshotDigest>,
    key: SnapshotKey,
    digest: SnapshotDigest,
) {
    snapshots.insert(key, digest);
    if snapshots.len() > MAX_SAVED_ALERTS {
        // The live alert queue evicts the oldest IDs first.
        snapshots.pop_first();
    }
}

pub fn new_session_id() -> String {
    format!(
        "{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        std::process::id()
    )
}

impl AlertJsonlWriter {
    pub fn open_default() -> Result<Self, String> {
        Self::open_default_for_fresh_session(&new_session_id())
    }

    pub fn open_default_for_session(session_id: &str) -> Result<Self, String> {
        Self::open(Self::default_path()?, session_id)
    }

    /// Only use this immediately after creating a new session ID, never when retrying saving.
    pub(crate) fn open_default_for_fresh_session(session_id: &str) -> Result<Self, String> {
        Self::open_session(Self::default_path()?, session_id, LogSession::Fresh)
    }

    fn default_path() -> Result<PathBuf, String> {
        Ok(dirs_next::data_dir()
            .ok_or("Packrat data directory is unavailable")?
            .join("packrat")
            .join("alerts.jsonl"))
    }

    pub(crate) fn open(path: PathBuf, session_id: &str) -> Result<Self, String> {
        Self::open_session(path, session_id, LogSession::Resume)
    }

    fn open_session(path: PathBuf, session_id: &str, session: LogSession) -> Result<Self, String> {
        let parent = path
            .parent()
            .ok_or("Alert JSONL path has no parent directory")?;
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("Create alert export directory: {error}"))?;

        let mut file = open_alert_file(&path)?;
        let mut latest_snapshots = BTreeMap::new();
        if matches!(session, LogSession::Resume) {
            let mut reader = BufReader::new(&mut file);
            let mut line = Vec::new();
            while next_alert_line(&mut reader, &mut line)
                .map_err(|error| format!("Read alert JSONL file {}: {error}", path.display()))?
            {
                let Some(record) = ExistingAlertRecord::decode(&line) else {
                    continue;
                };
                if record.session_id == session_id
                    && let Ok(encoded) = encode_alert_record(session_id, &record.alert)
                {
                    // Normalize parsed records rather than hashing their on-disk whitespace or key order.
                    remember(&mut latest_snapshots, snapshot_key(&record.alert), Sha256::digest(encoded).into());
                }
            }
        }
        let needs_separator = needs_line_separator(&mut file)?;
        Ok(Self {
            path,
            session_id: session_id.to_owned(),
            latest_snapshots,
            needs_separator,
            writer: file,
        })
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn backfill(
        &mut self,
        existing_alerts: &[AlertItem],
        pending_alerts: &[AlertItem],
    ) -> Result<(), String> {
        let latest: BTreeMap<_, _> = pending_alerts.iter()
            .chain(existing_alerts)
            .map(|alert| (snapshot_key(alert), alert))
            .collect();
        self.write_alerts(latest.into_values())
    }

    pub fn append_alerts(&mut self, alerts: &[AlertItem]) -> Result<(), String> {
        self.write_alerts(alerts.iter())
    }

    fn write_alerts<'a>(&mut self, alerts: impl IntoIterator<Item = &'a AlertItem>) -> Result<(), String> {
        #[cfg(unix)]
        let mut checked_rotation = false;
        for alert in alerts {
            let key = snapshot_key(alert);
            let mut record = encode_alert_record(&self.session_id, alert)?;
            let digest = Sha256::digest(&record).into();
            if self.latest_snapshots.get(&key) == Some(&digest) {
                continue;
            }
            if record.len() >= MAX_ALERT_LINE {
                return Err("Alert JSONL record exceeds the export size limit".into());
            }
            // Avoid filesystem checks on the packet path when there is no new snapshot.
            #[cfg(unix)]
            if !checked_rotation {
                self.follow_rotation()?;
                checked_rotation = true;
            }
            record.push(b'\n');
            if self.needs_separator {
                record.insert(0, b'\n');
            }
            // Cache only complete writes. A short write may leave a torn JSON line.
            if let Err(error) = self.writer.write_all(&record) {
                self.needs_separator = needs_line_separator(&mut self.writer).unwrap_or(true);
                return Err(format!("Write alert JSONL record: {error}"));
            }
            self.needs_separator = false;
            remember(&mut self.latest_snapshots, key, digest);
        }
        Ok(())
    }

    #[cfg(unix)]
    fn follow_rotation(&mut self) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;

        let current = self.writer.metadata()
            .map_err(|error| format!("Stat open alert JSONL file: {error}"))?;
        match std::fs::symlink_metadata(&self.path) {
            Ok(path) if (path.dev(), path.ino()) == (current.dev(), current.ino()) => {
                return verify_alert_file(&current, &self.path);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("Stat alert JSONL file {}: {error}", self.path.display())),
        }
        let mut replacement = open_alert_file(&self.path)?;
        self.needs_separator = needs_line_separator(&mut replacement)?;
        self.writer = replacement;
        Ok(())
    }
}

fn open_alert_file(path: &std::path::Path) -> Result<File, String> {
    let context = |error| format!("Open alert JSONL file {}: {error}", path.display());
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => verify_alert_file(&metadata, path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(context(error)),
    }
    let mut options = OpenOptions::new();
    options.create(true).read(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(context)?;
    verify_alert_file(&file.metadata().map_err(context)?, path)?;
    Ok(file)
}

fn verify_alert_file(metadata: &std::fs::Metadata, path: &std::path::Path) -> Result<(), String> {
    if !metadata.is_file() {
        return Err(format!("Alert JSONL path is not a regular file: {}", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        // SAFETY: geteuid has no arguments or caller invariants.
        let owner = unsafe { libc::geteuid() };
        if metadata.uid() != owner || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(format!(
                "Alert JSONL file must be owned by the capture user, have owner-only permissions (chmod 600), and have one hard link: {}",
                path.display(),
            ));
        }
    }
    Ok(())
}

fn needs_line_separator(file: &mut File) -> Result<bool, String> {
    if file.metadata().map_err(|error| error.to_string())?.len() > 0 {
        let mut last = [0];
        file.seek(SeekFrom::End(-1)).and_then(|_| file.read_exact(&mut last))
            .map_err(|error| format!("Read alert JSONL terminator: {error}"))?;
        Ok(last[0] != b'\n')
    } else {
        Ok(false)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/storage_alert_jsonl_tests.rs"]
mod tests;
