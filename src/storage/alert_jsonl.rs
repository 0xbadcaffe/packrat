//! Append-only, versioned JSONL export of Alert Center findings.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use crate::analysis::alert_center::AlertItem;

pub(super) const MAX_ALERT_LINE: usize = 1_048_576;
const MAX_SAVED_ALERTS: usize = 4096;

type SnapshotKey = (u64, Option<[u8; 32]>);
type SnapshotDigest = [u8; 32];

pub struct AlertJsonlWriter {
    path: PathBuf,
    session_id: String,
    latest_snapshots: BTreeMap<SnapshotKey, SnapshotDigest>,
    needs_separator: bool,
    writer: BufWriter<File>,
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

fn snapshot_digest(alert: &AlertItem) -> Result<SnapshotDigest, String> {
    let bytes = serde_json::to_vec(alert).map_err(|error| format!("Serialize alert snapshot: {error}"))?;
    Ok(Sha256::digest(bytes).into())
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
        Self::open_default_for_session(&new_session_id())
    }

    pub fn open_default_for_session(session_id: &str) -> Result<Self, String> {
        let path = dirs_next::data_dir()
            .ok_or("Packrat data directory is unavailable")?
            .join("packrat")
            .join("alerts.jsonl");
        Self::open(path, session_id)
    }

    fn open(path: PathBuf, session_id: &str) -> Result<Self, String> {
        let parent = path
            .parent()
            .ok_or("Alert JSONL path has no parent directory")?;
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("Create alert export directory: {error}"))?;

        let mut latest_snapshots = BTreeMap::new();
        match File::open(&path) {
            Ok(existing) => {
                let mut reader = BufReader::new(existing);
                let mut line = Vec::new();
                while next_alert_line(&mut reader, &mut line)
                    .map_err(|error| format!("Read alert JSONL file {}: {error}", path.display()))?
                {
                    let Some(record) = ExistingAlertRecord::decode(&line) else {
                        continue;
                    };
                    if record.session_id == session_id && let Ok(digest) = snapshot_digest(&record.alert) {
                        remember(&mut latest_snapshots, snapshot_key(&record.alert), digest);
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("Read alert JSONL file {}: {error}", path.display())),
        }
        let (writer, needs_separator) = open_append(&path)?;
        Ok(Self {
            path,
            session_id: session_id.to_owned(),
            latest_snapshots,
            needs_separator,
            writer,
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
            let digest = snapshot_digest(alert)?;
            if self.latest_snapshots.get(&key) == Some(&digest) {
                continue;
            }
            let mut record = serde_json::to_vec(&AlertRecord {
                schema_version: 1,
                record_type: "alert",
                session_id: &self.session_id,
                alert,
            })
            .map_err(|error| format!("Serialize alert JSONL record: {error}"))?;
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
            self.writer
                .write_all(&record)
                .map_err(|error| format!("Write alert JSONL record: {error}"))?;
            self.needs_separator = false;
            remember(&mut self.latest_snapshots, key, digest);
        }
        self.writer
            .flush()
            .map_err(|error| format!("Flush alert JSONL file: {error}"))
    }

    #[cfg(unix)]
    fn follow_rotation(&mut self) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;

        let current = self.writer.get_ref().metadata()
            .map_err(|error| format!("Stat open alert JSONL file: {error}"))?;
        match std::fs::metadata(&self.path) {
            Ok(path) if (path.dev(), path.ino()) == (current.dev(), current.ino()) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("Stat alert JSONL file {}: {error}", self.path.display())),
        }
        self.writer.flush()
            .map_err(|error| format!("Flush rotated alert JSONL file: {error}"))?;
        (self.writer, self.needs_separator) = open_append(&self.path)?;
        Ok(())
    }
}

fn open_append(path: &std::path::Path) -> Result<(BufWriter<File>, bool), String> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)
        .map_err(|error| format!("Open alert JSONL file {}: {error}", path.display()))?;
    let needs_separator = if file.metadata().map_err(|error| error.to_string())?.len() > 0 {
        let mut last = [0];
        file.seek(SeekFrom::End(-1)).and_then(|_| file.read_exact(&mut last))
            .map_err(|error| format!("Read alert JSONL terminator: {error}"))?;
        last[0] != b'\n'
    } else {
        false
    };
    Ok((BufWriter::new(file), needs_separator))
}

#[cfg(test)]
#[path = "../../tests/unit/storage_alert_jsonl_tests.rs"]
mod tests;
