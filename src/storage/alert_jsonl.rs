//! Append-only, versioned JSONL export of Alert Center findings.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use crate::analysis::alert_center::AlertItem;

pub struct AlertJsonlWriter {
    path: PathBuf,
    session_id: String,
    writer: BufWriter<File>,
}

#[derive(serde::Serialize)]
struct AlertRecord<'a> {
    schema_version: u8,
    record_type: &'static str,
    session_id: &'a str,
    alert: &'a AlertItem,
}

impl AlertJsonlWriter {
    pub fn open_default() -> Result<Self, String> {
        let path = dirs_next::data_dir()
            .ok_or("Packrat data directory is unavailable")?
            .join("packrat")
            .join("alerts.jsonl");
        let parent = path
            .parent()
            .ok_or("Alert JSONL path has no parent directory")?;
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("Create alert export directory: {error}"))?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| format!("Open alert JSONL file {}: {error}", path.display()))?;
        Ok(Self {
            path,
            session_id: format!(
                "{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
                std::process::id()
            ),
            writer: BufWriter::new(file),
        })
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn append_alerts(&mut self, alerts: &[AlertItem]) -> Result<(), String> {
        if alerts.is_empty() {
            return Ok(());
        }
        for alert in alerts {
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
        }
        self.writer
            .flush()
            .map_err(|error| format!("Flush alert JSONL file: {error}"))
    }
}
