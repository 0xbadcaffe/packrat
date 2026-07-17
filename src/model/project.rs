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

pub const SCHEMA_VERSION: u32 = 3;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum SavedInvestigationItem {
    Packet(u64),
    Stream(String),
    Host(String),
    Alert(u64),
    Object(u64),
    GraphNode(String),
    Note(u64),
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
    #[serde(default)]
    pub alert_items: Vec<AlertItem>,
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
            alert_items: Vec::new(),
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
mod tests {
    use super::*;
    use crate::analysis::alert_center::{AlertDisposition, AlertItem};

    #[test]
    fn older_projects_load_with_empty_operational_state() {
        let state = ProjectState::new("legacy", ProjectSaveMode::Lightweight);
        let mut json = serde_json::to_value(state).unwrap();
        let object = json.as_object_mut().unwrap();
        for field in [
            "alert_items",
            "alert_automation",
            "investigation_items",
            "active_investigation",
            "investigation_tray_open",
            "guard_simulation",
            "active_tab",
            "embedded_packets",
        ] {
            object.remove(field);
        }

        let restored: ProjectState = serde_json::from_value(json).unwrap();
        assert!(restored.alert_items.is_empty());
        assert_eq!(restored.alert_automation, AutomationMode::Off);
        assert!(restored.investigation_items.is_empty());
        assert!(restored.guard_simulation.is_empty());
        assert_eq!(restored.active_tab, 0);
    }

    #[test]
    fn operational_investigation_state_round_trips() {
        let mut state = ProjectState::new("case", ProjectSaveMode::Portable);
        state.alert_automation = AutomationMode::Triage;
        state.alert_items.push(AlertItem {
            id: 7,
            packet_no: 42,
            source: "IDS".into(),
            severity: "HIGH".into(),
            title: "Probe".into(),
            detail: "Repeated connection attempts".into(),
            disposition: AlertDisposition::Reviewing,
            priority: 80,
            recommendation: Some("Inspect the stream".into()),
            correlation_key: "203.0.113.9>10.0.0.5".into(),
            hit_count: 3,
            first_packet: 40,
            last_packet: 42,
            first_seen: 1.0,
            last_seen: 3.0,
        });
        state.investigation_items = vec![
            SavedInvestigationItem::Packet(42),
            SavedInvestigationItem::Host("203.0.113.9".into()),
        ];
        state.active_investigation = Some(1);
        state.investigation_tray_open = true;
        state.active_tab = 9;
        state.embedded_packets.push(Packet {
            no: 42,
            timestamp: 3.0,
            src: "203.0.113.9".into(),
            dst: "10.0.0.5".into(),
            protocol: "TCP".into(),
            length: 4,
            info: "portable evidence".into(),
            src_port: Some(40000),
            dst_port: Some(443),
            vlan_id: None,
            vlan_pcp: None,
            vlan_dei: None,
            outer_vlan_id: None,
            bytes: vec![1, 2, 3, 4],
        });

        let restored: ProjectState = serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
        assert_eq!(restored.alert_items[0].disposition, AlertDisposition::Reviewing);
        assert_eq!(restored.alert_automation, AutomationMode::Triage);
        assert_eq!(restored.investigation_items, state.investigation_items);
        assert_eq!(restored.active_investigation, Some(1));
        assert!(restored.investigation_tray_open);
        assert_eq!(restored.active_tab, 9);
        assert_eq!(restored.embedded_packets.len(), 1);
        assert_eq!(restored.embedded_packets[0].bytes, vec![1, 2, 3, 4]);
    }
}
