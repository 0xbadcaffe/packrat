//! Session persistence — save and restore analysis state.
//!
//! Serializes the analyst notebook, tags, IOC lists, and rule engine
//! to a JSON file on disk.

use std::path::{Path, PathBuf};
use anyhow::Result;

use crate::analysis::notebook::Notebook;
use crate::model::tags::TagStore;

// ─── Session data ─────────────────────────────────────────────────────────────

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SessionData {
    pub version:    u32,
    pub created_at: f64,
    pub pcap_path:  Option<String>,
    pub notebook:   Notebook,
    pub tags:       TagStore,
    pub notes:      String,
}

impl SessionData {
    pub fn new() -> Self {
        Self {
            version:    1,
            created_at: now(),
            ..Default::default()
        }
    }
}

// ─── Session store ────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct SessionStore {
    pub path:    Option<PathBuf>,
    pub session: SessionData,
    pub dirty:   bool,
}

impl SessionStore {
    pub fn new() -> Self {
        Self { session: SessionData::new(), ..Default::default() }
    }

    /// Load a session from disk.
    pub fn load(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let data = std::fs::read_to_string(path)?;
        self.session = serde_json::from_str(&data)?;
        self.path = Some(path.to_path_buf());
        self.dirty = false;
        Ok(())
    }

    /// Save session to its current path (or the given path).
    pub fn save(&mut self, path: Option<impl AsRef<Path>>) -> Result<PathBuf> {
        let target = if let Some(p) = path {
            let p = p.as_ref().to_path_buf();
            self.path = Some(p.clone());
            p
        } else if let Some(ref p) = self.path {
            p.clone()
        } else {
            anyhow::bail!("no session path set");
        };

        let json = serde_json::to_string_pretty(&self.session)?;
        std::fs::write(&target, json)?;
        self.dirty = false;
        Ok(target)
    }

    pub fn mark_dirty(&mut self) { self.dirty = true; }

    pub fn auto_save_path() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push("packrat_session.json");
        p
    }
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
