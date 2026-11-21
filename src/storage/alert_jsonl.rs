//! Append-only, versioned JSONL export of Alert Center findings.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

use crate::analysis::alert_center::AlertItem;

pub struct AlertJsonlWriter {
    path: PathBuf,
    session_id: String,
    written_snapshots: HashSet<String>,
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
struct ExistingAlertRecord {
    session_id: String,
    alert: AlertItem,
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

        let mut written_snapshots = HashSet::new();
        match File::open(&path) {
            Ok(existing) => {
                for line in BufReader::new(existing).lines().map_while(Result::ok) {
                    let Ok(record) = serde_json::from_str::<ExistingAlertRecord>(&line) else {
                        continue;
                    };
                    if record.session_id == session_id {
                        if let Ok(snapshot) = serde_json::to_string(&record.alert) {
                            written_snapshots.insert(snapshot);
                        }
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("Read alert JSONL file {}: {error}", path.display())),
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| format!("Open alert JSONL file {}: {error}", path.display()))?;
        Ok(Self {
            path,
            session_id: session_id.to_owned(),
            written_snapshots,
            writer: BufWriter::new(file),
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
        let mut alerts = Vec::with_capacity(existing_alerts.len() + pending_alerts.len());
        alerts.extend_from_slice(existing_alerts);
        alerts.extend_from_slice(pending_alerts);
        self.append_alerts(&alerts)
    }

    pub fn append_alerts(&mut self, alerts: &[AlertItem]) -> Result<(), String> {
        if alerts.is_empty() {
            return Ok(());
        }
        for alert in alerts {
            let snapshot = serde_json::to_string(alert)
                .map_err(|error| format!("Serialize alert snapshot: {error}"))?;
            if self.written_snapshots.contains(&snapshot) {
                continue;
            }
            serde_json::to_writer(
                &mut self.writer,
                &AlertRecord {
                    schema_version: 1,
                    record_type: "alert",
                    session_id: &self.session_id,
                    alert,
                },
            )
            .map_err(|error| format!("Serialize alert JSONL record: {error}"))?;
            self.writer
                .write_all(b"\n")
                .map_err(|error| format!("Write alert JSONL record: {error}"))?;
            self.written_snapshots.insert(snapshot);
        }
        self.writer
            .flush()
            .map_err(|error| format!("Flush alert JSONL file: {error}"))
    }
}

#[cfg(test)]
#[path = "../../tests/unit/storage_alert_jsonl_tests.rs"]
mod tests;
