use crate::engine::AnalysisCore;
use std::collections::VecDeque;
use tokio::sync::mpsc::Sender;

use crate::analysis::alert_center::AutomationMode;
use crate::analysis::diff::DiffEngine;
use crate::analysis::display_filter::DisplayFilter;
use crate::analysis::evidence_vault::EvidenceVault;
use crate::analysis::incident::{IncidentSource, IncidentStore};
use crate::analysis::jobs::JobQueue;
use crate::analysis::net_registry::NetRegistry;
use crate::analysis::notebook::Notebook;
use crate::analysis::packet_compare::{self, PacketComparison};
use crate::analysis::packet_fields::{self, PacketField};
use crate::analysis::protocol_workbench::ProtocolWorkbench;
use crate::analysis::route_ledger::RouteLedger;
use crate::analysis::socket_scope::SocketScope;
use crate::analysis::stream::{ReassembledStream, StreamKey, StreamOverlayState};
use crate::analysis::telemetry::{TelemetryHub, TelemetrySnapshot};
use crate::analysis::traffic_latch::{
    CommandLatch, LatchAction, LatchMode, NftablesLatch, TrafficLatch,
};
use crate::analysis::wire_pulse::WirePulse;
use crate::capture::CaptureSource;
use crate::craft::CraftState;
use crate::dissector::DissectorDef;
use crate::export::pcapng::PcapNgWriter;
use crate::filter::PacketFilter;
use crate::model::evidence::Severity as EvidenceSeverity;
use crate::model::project::{ProjectSaveMode, SavedInvestigationItem};
use crate::model::tags::TagStore;
use crate::net::flow::{FlowKey, FlowSort};
use crate::net::lua_plugin::PluginManager;
use crate::net::packet::Packet;
use crate::net::packet::TreeSection;
use crate::pcap_replay::ReplayState;
use crate::scan::ScanState;
use crate::sim::capture::SimulatedCapture;
use crate::sim::dynamic::DynEntry;
use crate::storage::project_store;
use crate::storage::theme_store;
use crate::tabs::{Tab, Workspace};
use crate::traceroute::TracerouteState;
use crate::ui::autopsy_overlay::AutopsyState;
use crate::ui::project_manager::ProjectManagerState;

const MAX_PACKETS: usize = 10_000;
pub const INCIDENT_ANALYSIS_SECTION: usize = 11;
pub const SETTINGS_COUNT: usize = 8;

mod capture_control;
mod constructor;
mod feeds_scenario;
mod graph_state;
pub use graph_state::{GraphUiModeState, GraphUiState};
mod header_inspection;
mod incidents;
mod ingest;
mod inspection_tools;
mod investigation;
mod navigation;
mod packet_list;
mod project;
mod runtime;
mod search;
mod settings;
mod startup;
mod strings;
mod types;
use startup::list_interfaces;
pub use startup::{CliAction, StartupMode, StartupOptions, parse_startup_args, usage};
pub use types::*;

pub struct App {
    pub core: AnalysisCore,
    pub active_tab: Tab,
    /// Recently visited screens, newest last. Modal overlays are not included.
    pub navigation_history: Vec<Tab>,
    pub packets: VecDeque<Packet>,
    packet_index_base: usize,
    pub filtered: VecDeque<usize>,
    pub selected: Option<usize>,
    pub total_bytes: u64,
    pub packet_counter: u64,
    pub capturing: bool,
    capture_handle: Option<crate::capture::CaptureTask>,
    packet_tx: Sender<Packet>,
    pub picking_iface: bool,
    pub iface_list: Vec<String>,
    pub iface_sel: usize,
    pub selected_iface: String,
    pub filter: PacketFilter,
    pub rate_history: Vec<u32>,
    pub rate_this_sec: u32,
    rate_tick: u32,
    pub dyn_log: Vec<DynEntry>,
    pub dyn_scroll: usize,
    pub analysis_section: usize,
    pub strings_filter: String,
    pub _hex_scroll: u16,
    pub recording: bool,
    restoring_project: bool,
    pub pcap_path: String,
    pcap_writer: Option<PcapNgWriter<std::io::BufWriter<std::fs::File>>>,
    pub show_help: bool,
    pub help_scroll: u16,
    pub dissectors: Vec<DissectorDef>,
    pub strings_search_active: bool,
    pub strings_selected: Option<usize>,
    pub strings_scroll: usize,
    pub flows_selected: Option<usize>,
    pub flows_sort: FlowSort,
    pub stream_overlay: Option<StreamOverlayState>,
    pub packet_comparison: Option<PacketComparison>,
    pub lua_plugins: PluginManager,
    pub lua_reload_msg: Option<String>,
    pub craft: CraftState,
    pub traceroute: TracerouteState,
    pub scan: ScanState,
    pub replay: ReplayState,
    pub security_tab: SecuritySubTab,
    pub security_scroll: usize,
    pub scanner_scroll: usize,
    pub replay_editing: bool,
    /// Whether the PCAP instant-import path input is active.
    pub pcap_import_editing: bool,
    pub pcap_import_path: String,
    pub scan_editing: bool,
    // ─── Phase 1–4 analysis state ──────────────────────────────────────────────
    pub tag_store: TagStore,
    pub notebook: Notebook,
    pub packet_archive: Option<crate::storage::packet_archive::ArchiveWorker>,
    pub evidence_vault: EvidenceVault,
    pub telemetry: TelemetryHub,
    pub socket_scope: SocketScope,
    pub route_ledger: RouteLedger,
    pub traffic_latch: TrafficLatch,
    live_response_eligible: bool,
    processing_live_packet: bool,
    live_response_incidents: std::collections::HashSet<u64>,
    pub response_preview: Vec<LatchAction>,
    pub latch_helper_path: Option<std::path::PathBuf>,
    pub wire_pulse: WirePulse,
    pub net_registry: NetRegistry,
    pub reputation_helper_path: Option<std::path::PathBuf>,
    pub capture_helper_path: Option<std::path::PathBuf>,
    /// Visible only while an unreviewed critical incident needs attention.
    pub alert_overlay_open: bool,
    pub workbench: ProtocolWorkbench,
    pub diff_engine: DiffEngine,
    pub diff_scroll: usize,
    /// Cloned packet snapshot used as baseline for differential analysis.
    pub diff_baseline: Vec<crate::net::packet::Packet>,
    pub job_queue: JobQueue,
    pub display_filter: DisplayFilter,
    // Notebook UI state
    pub notebook_scroll: usize,
    pub notebook_input: String,
    pub notebook_editing: bool,
    pub notebook_searching: bool,
    pub notebook_search: String,
    // Hosts UI state
    pub hosts_scroll: usize,
    pub hosts_search: String,
    pub hosts_searching: bool,
    pub hosts_tagging: bool,
    pub hosts_tag_input: String,
    // TLS UI state
    pub tls_scroll: usize,
    pub tls_selected: usize,
    pub encrypted_view: EncryptedView,
    // Objects UI state
    pub objects_scroll: usize,
    pub objects_subtab: ObjectsSubTab,
    pub yara_rules_scroll: usize,
    pub yara_matches_scroll: usize,
    // Rules UI state
    pub rules_scroll: usize,
    // ─── Operator graph ────────────────────────────────────────────────────────
    pub graph_ui: GraphUiState,
    // ─── Global command palette ────────────────────────────────────────────────
    pub search_open: bool,
    pub search_query: String,
    pub search_results: Vec<SearchResult>,
    pub search_selected: usize,
    // ─── Protocol Autopsy overlay ──────────────────────────────────────────────
    pub autopsy_state: Option<AutopsyState>,
    // ─── Theme ────────────────────────────────────────────────────────────────
    /// Name of the active built-in theme.
    pub selected_theme_name: String,
    /// Whether the theme picker overlay is shown.
    pub theme_picker_open: bool,
    pub theme_picker_cursor: usize,
    /// Workspace-local view drawer state.
    pub view_menu_open: bool,
    pub view_menu_cursor: usize,
    pub worklist: InvestigationTray,
    pub investigation_view: InvestigationView,
    pub investigation_scroll: usize,
    pub header_cursor: usize,
    pub byte_cursor: usize,
    pub header_searching: bool,
    pub header_search: String,
    pub settings_open: bool,
    pub settings_cursor: usize,
    pub auto_scroll: bool,
    pub preferred_workspace: Workspace,
    persist_preferences: bool,
    // ─── Project management ────────────────────────────────────────────────────
    /// Name of the currently open project (None = ad-hoc workspace).
    pub current_project_name: Option<String>,
    /// Filesystem path of the currently open project file.
    pub current_project_path: Option<String>,
    /// True when there are unsaved changes since the last save.
    pub project_dirty: bool,
    /// Whether the project manager overlay is shown.
    pub project_manager_open: bool,
    pub project_manager: ProjectManagerState,
    // ─── Status / feedback message (transient, cleared after a few ticks) ─────
    pub status_msg: Option<String>,
    status_msg_ticks: u8,
}

fn saved_investigation_item(item: &InvestigationItem) -> SavedInvestigationItem {
    match item {
        InvestigationItem::Packet(value) => SavedInvestigationItem::Packet(*value),
        InvestigationItem::Stream(value) => SavedInvestigationItem::Stream(value.clone()),
        InvestigationItem::Host(value) => SavedInvestigationItem::Host(value.clone()),
        InvestigationItem::Alert(value) => SavedInvestigationItem::Alert(*value),
        InvestigationItem::Object(value) => SavedInvestigationItem::Object(*value),
        InvestigationItem::GraphNode(value) => SavedInvestigationItem::GraphNode(value.clone()),
        InvestigationItem::Note(value) => SavedInvestigationItem::Note(*value),
    }
}

fn restore_investigation_tray(
    state: &crate::model::project::ProjectState,
) -> Result<InvestigationTray, String> {
    let mut tray = InvestigationTray::default();
    tray.items = state
        .investigation_items
        .iter()
        .cloned()
        .map(restored_investigation_item)
        .collect();
    let packet_nos: std::collections::HashSet<u64> = tray.packet_nos().into_iter().collect();
    for packet in state.pinned_packets.iter().chain(&state.embedded_packets) {
        if packet_nos.contains(&packet.no) {
            tray.pin_packet(packet)?;
        }
    }
    tray.active = state
        .active_investigation
        .filter(|index| *index < tray.items.len());
    tray.open = state.investigation_tray_open && !tray.items.is_empty();
    Ok(tray)
}

fn restored_investigation_item(item: SavedInvestigationItem) -> InvestigationItem {
    match item {
        SavedInvestigationItem::Packet(value) => InvestigationItem::Packet(value),
        SavedInvestigationItem::Stream(value) => InvestigationItem::Stream(value),
        SavedInvestigationItem::Host(value) => InvestigationItem::Host(value),
        SavedInvestigationItem::Alert(value) => InvestigationItem::Alert(value),
        SavedInvestigationItem::Object(value) => InvestigationItem::Object(value),
        SavedInvestigationItem::GraphNode(value) => InvestigationItem::GraphNode(value),
        SavedInvestigationItem::Note(value) => InvestigationItem::Note(value),
    }
}

/// Convert a byte slice to a printable ASCII line (non-printable → '.').
fn printable_line(data: &[u8]) -> String {
    data.iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

#[cfg(test)]
#[path = "../../tests/unit/app.rs"]
mod tests;
