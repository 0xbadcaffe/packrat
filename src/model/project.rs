//! Project model — named investigation container persisted across sessions.
//!
//! A Project is the user's working container for an investigation.
//! It stores notebook notes, host tags, the active filter, PCAP references,
//! and carved-object metadata — everything needed to continue where they left off.

use std::collections::HashMap;

use crate::analysis::notebook::Notebook;
use crate::model::tags::TagStore;
use crate::storage::case_bundle::ObjectEntry;

pub const SCHEMA_VERSION: u32 = 1;

// ─── Core types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProjectMetadata {
    pub id:              u64,
    pub name:            String,
    pub description:     Option<String>,
    pub created_at:      f64,
    pub last_opened_at:  f64,
    pub schema_version:  u32,
    pub save_mode:       ProjectSaveMode,
}

impl ProjectMetadata {
    pub fn new(name: impl Into<String>, mode: ProjectSaveMode) -> Self {
        Self {
            id:             gen_id(),
            name:           name.into(),
            description:    None,
            created_at:     now(),
            last_opened_at: now(),
            schema_version: SCHEMA_VERSION,
            save_mode:      mode,
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ProjectSaveMode {
    /// References external PCAP files; smaller project file.
    Lightweight,
    /// Embeds all required artifacts; fully portable.
    Portable,
}

impl std::fmt::Display for ProjectSaveMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Lightweight => write!(f, "Lightweight"), Self::Portable => write!(f, "Portable") }
    }
}

// ─── Full project state ───────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ProjectState {
    pub metadata:       ProjectMetadata,
    pub notebook:       Notebook,
    pub tag_store:      TagStore,
    pub active_filter:  String,
    /// Host IP → sorted tag list (restored into HostInventory on load).
    pub host_tags:      HashMap<String, Vec<String>>,
    /// Carved-object metadata snapshots.
    pub carved_objects: Vec<ObjectEntry>,
    /// External PCAP paths (lightweight mode).
    pub pcap_refs:      Vec<String>,
    /// Embedded raw PCAP bytes (portable mode, optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcap_data:      Option<Vec<u8>>,
}

impl ProjectState {
    pub fn new(name: impl Into<String>, mode: ProjectSaveMode) -> Self {
        Self {
            metadata:       ProjectMetadata::new(name, mode),
            notebook:       Notebook::default(),
            tag_store:      TagStore::default(),
            active_filter:  String::new(),
            host_tags:      HashMap::new(),
            carved_objects: Vec::new(),
            pcap_refs:      Vec::new(),
            pcap_data:      None,
        }
    }
}

// ─── Recent project pointer ───────────────────────────────────────────────────

/// Stored in `~/.config/packrat/recent_projects.json`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecentProject {
    pub name:        String,
    pub path:        String,
    pub last_opened: f64,
    pub description: Option<String>,
    pub save_mode:   ProjectSaveMode,
}

impl RecentProject {
    pub fn last_opened_display(&self) -> String {
        let secs = self.last_opened as u64;
        // Convert epoch seconds to a rough date string without chrono
        // epoch 0 = 1970-01-01; we just show "YYYY-MM-DD HH:MM" approximately
        let days = secs / 86400;
        let year = 1970 + days / 365;
        let month = ((days % 365) / 30).clamp(0, 11) + 1;
        let day   = ((days % 365) % 30) + 1;
        let h = (secs % 86400) / 3600;
        let m = (secs % 3600) / 60;
        format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}")
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn gen_id() -> u64 {
    (now() * 1_000.0) as u64
}
