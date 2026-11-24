//! Project model — named investigation container persisted across sessions.
//!
//! A Project is the user's working container for an investigation.
//! It stores notebook notes, host tags, the active filter, PCAP references,
//! and carved-object metadata — everything needed to continue where they left off.

use std::collections::HashMap;

use crate::analysis::notebook::Notebook;
use crate::analysis::alert_center::{AlertItem, AutomationMode};
use crate::analysis::traffic_latch::LatchAction;
use crate::model::tags::TagStore;
use crate::storage::case_bundle::ObjectEntry;
use crate::net::packet::Packet;

pub const SCHEMA_VERSION: u32 = 9;
// Stable project-format index, shared by headless export and the terminal UI.
pub(crate) const INVESTIGATE_TAB_INDEX: usize = 1;
pub(crate) const MAX_PINNED_PACKETS: usize = 1024;
pub(crate) const MAX_PINNED_BYTES: usize = 64 * 1024 * 1024;

pub(crate) fn pinned_packet_cost(packet: &Packet) -> usize {
    let metadata = packet.capture.as_ref().map_or(0, |capture| {
        capture.interface_name.as_ref().map_or(0, String::len)
            + capture.comments.iter().map(String::len).sum::<usize>()
    });
    std::mem::size_of::<Packet>() + packet.bytes.len() + packet.src.len() + packet.dst.len()
        + packet.protocol.len() + packet.info.len() + metadata
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum SavedInvestigationItem {
    Packet(u64),
    Stream(String),
    Host(String),
    Alert(u64),
    UnresolvedAlert(u64),
    AlertRef { id: u64, capture_id: Option<String> },
    Object(u64),
    GraphNode(String),
    Note(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchivedFrameOutcome {
    Complete,
    Truncated,
    LengthUnknown,
    Missing,
    Unreadable,
    OmittedAtLimit,
}

impl ArchivedFrameOutcome {
    pub(crate) fn included(self) -> bool {
        matches!(self, Self::Complete | Self::Truncated | Self::LengthUnknown)
    }
}

impl From<crate::storage::alert_evidence::FrameStatus> for ArchivedFrameOutcome {
    fn from(status: crate::storage::alert_evidence::FrameStatus) -> Self {
        use crate::storage::alert_evidence::FrameStatus;
        match status {
            FrameStatus::Complete => Self::Complete,
            FrameStatus::Truncated => Self::Truncated,
            FrameStatus::LengthUnknown => Self::LengthUnknown,
            FrameStatus::Missing => Self::Missing,
            FrameStatus::Unreadable => Self::Unreadable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AlertArchiveReport {
    pub alert_id: u64,
    pub capture_id: String,
    pub session_id: Option<String>,
    pub frames: std::collections::BTreeMap<u64, ArchivedFrameOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_sha256: Option<std::collections::BTreeMap<u64, String>>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    pub local_fallback_frames: std::collections::BTreeSet<u64>,
}

pub(crate) fn packet_bytes_sha256(packet: &Packet) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(&packet.bytes))
}

impl AlertArchiveReport {
    pub(crate) fn validate(&self) -> Result<(), String> {
        use crate::storage::packet_archive::valid_capture_id;

        if self.alert_id == 0 || !valid_capture_id(&self.capture_id)
            || self.session_id.as_deref().is_some_and(|id| !valid_capture_id(id))
            || self.frames.is_empty() || self.frames.contains_key(&0)
            || self.frames.len() > crate::analysis::alert_center::MAX_ALERT_PACKET_REFS + 3
        {
            return Err("Invalid saved alert archive report".into());
        }
        if let Some(digests) = &self.retained_sha256
            && (!digests.keys().eq(self.frames.iter().filter_map(|(frame, outcome)| outcome.included().then_some(frame)))
                || digests.values().any(|digest| digest.len() != 64 ||
                    !digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))))
        {
            return Err("Invalid saved alert archive frame digests".into());
        }
        if !self.local_fallback_frames.iter().all(|frame| self.frames.get(frame).is_some_and(|outcome| outcome.included())) {
            return Err("Invalid saved alert local fallback references".into());
        }
        Ok(())
    }
}

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
    /// Parsed packet snapshots included only by Portable projects.
    #[serde(default)]
    pub embedded_packets: Vec<Packet>,
    /// Pinned evidence survives live-buffer eviction in either save mode.
    #[serde(default)]
    pub pinned_packets: Vec<Packet>,
    /// Capture IDs for scoped pins. Older projects intentionally have no mapping.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub pinned_packet_scopes: std::collections::BTreeMap<u64, String>,
    #[serde(default)]
    pub incident_state: Option<crate::analysis::incident::IncidentSnapshot>,
    #[serde(default)]
    pub endpoint_evidence: Vec<crate::analysis::impact::EndpointEvidence>,
    #[serde(default)]
    pub alert_items: Vec<AlertItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert_archive_report: Option<AlertArchiveReport>,
    #[serde(default)]
    pub alert_automation: AutomationMode,
    #[serde(default)]
    pub investigation_items: Vec<SavedInvestigationItem>,
    #[serde(default)]
    pub active_investigation: Option<usize>,
    #[serde(default)]
    pub investigation_tray_open: bool,
    #[serde(default)]
    pub guard_simulation: Vec<LatchAction>,
    #[serde(default)]
    pub active_tab: usize,
}

impl ProjectState {
    pub(crate) fn validate_archive_evidence(&self) -> Result<(), String> {
        let Some(report) = &self.alert_archive_report else { return Ok(()) };
        report.validate()?;
        let Some(digests) = &report.retained_sha256 else { return Ok(()) };
        let mut verified = std::collections::HashSet::new();
        for packet in &self.pinned_packets {
            let Some(expected) = digests.get(&packet.no) else { continue };
            let outcome = ArchivedFrameOutcome::from(crate::storage::alert_evidence::frame_status(packet));
            if self.pinned_packet_scopes.get(&packet.no) != Some(&report.capture_id)
                || !verified.insert(packet.no) || packet_bytes_sha256(packet) != *expected
                || report.frames.get(&packet.no) != Some(&outcome)
            {
                return Err(format!("Saved archive evidence does not match its export record for frame #{}", packet.no));
            }
        }
        Ok(())
    }

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
            embedded_packets: Vec::new(),
            pinned_packets: Vec::new(),
            pinned_packet_scopes: Default::default(),
            incident_state: None,
            endpoint_evidence: Vec::new(),
            alert_items: Vec::new(),
            alert_archive_report: None,
            alert_automation: AutomationMode::Off,
            investigation_items: Vec::new(),
            active_investigation: None,
            investigation_tray_open: false,
            guard_simulation: Vec::new(),
            active_tab: 0,
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

#[cfg(test)]
#[path = "../../tests/unit/model_project_tests.rs"]
mod tests;
