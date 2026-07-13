use std::collections::VecDeque;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;

use crate::analysis::carving::{Carver, CarvedObject};
use crate::analysis::yara::YaraEngine;
use crate::model::project::ProjectSaveMode;
use crate::model::evidence::Severity as EvidenceSeverity;
use crate::storage::project_store;
use crate::storage::theme_store;
use crate::ui::autopsy_overlay::AutopsyState;
use crate::ui::project_manager::ProjectManagerState;
use crate::analysis::diff::DiffEngine;
use crate::analysis::display_filter::DisplayFilter;
use crate::analysis::ioc::IocEngine;
use crate::analysis::incident::{IncidentSource, IncidentStore};
use crate::analysis::evidence_vault::EvidenceVault;
use crate::analysis::telemetry::{TelemetryHub, TelemetrySnapshot};
use crate::analysis::socket_scope::SocketScope;
use crate::analysis::route_ledger::RouteLedger;
use crate::analysis::quic_scope::QuicScope;
use crate::analysis::traffic_latch::{CommandLatch, LatchMode, NftablesLatch, TrafficLatch};
use crate::analysis::wire_pulse::WirePulse;
use crate::analysis::net_registry::NetRegistry;
use crate::analysis::jobs::JobQueue;
use crate::analysis::notebook::Notebook;
use crate::analysis::operator_graph::{GraphUiState, OperatorGraphEngine};
use crate::analysis::packet_fields::{self, PacketField};
use crate::analysis::protocol_workbench::ProtocolWorkbench;
use crate::analysis::rules::RuleEngine;
use crate::analysis::rules::Action as RuleAction;
use crate::analysis::stream::{ReassembledStream, StreamAssembler, StreamKey};
use crate::analysis::timeline::ProtocolTimelines;
use crate::analysis::tls::TlsTracker;
use crate::analysis::vlan::VlanIntel;
use crate::capture::CaptureSource;
use crate::craft::CraftState;
use crate::model::hosts::HostInventory;
use crate::model::tags::TagStore;
use crate::net::inspector::CredentialHit;
use crate::net::security::SecurityEngine;
use crate::pcap_replay::ReplayState;
use crate::scan::ScanState;
use crate::sim::capture::SimulatedCapture;
use crate::sim::dynamic::DynEntry;
use crate::export::PcapWriter;
use crate::filter::PacketFilter;
use crate::net::flow::{FlowTracker, FlowSort, FlowKey};
use crate::net::lua_plugin::PluginManager;
use crate::net::packet::Packet;
use crate::dissector::DissectorDef;
use crate::net::packet::TreeSection;
use crate::tabs::{Tab, Workspace};
use crate::traceroute::TracerouteState;

const MAX_PACKETS: usize = 10_000;
pub const INCIDENT_ANALYSIS_SECTION: usize = 11;

/// Sub-sections within the Security tab
#[derive(Debug, Clone, PartialEq)]
pub enum SecuritySubTab {
    Ids,
    Credentials,
    OsFingerprint,
    ArpWatch,
    DnsTunnel,
    HttpAnalytics,
    TlsWeakness,
    BruteForce,
    VulnHits,
    IocHits,
    VlanIntel,
    ProcessScope,
    RoutePolicy,
    WirePulse,
    NetRegistry,
    Replay,
}

/// A single result from the global command palette search.
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// Short category label (e.g., "Packet", "Host", "IOC Hit", "Rule").
    pub source:   &'static str,
    /// Primary display label shown in the list.
    pub label:    String,
    /// Secondary detail shown alongside the label.
    pub detail:   String,
    /// Tab to switch to when this result is selected.
    pub jump_tab: Tab,
    /// Optional scroll position to apply after tab switch.
    pub scroll:   usize,
}

/// Sub-panels within the Objects tab
#[derive(Debug, Clone, PartialEq, Default)]
pub enum ObjectsSubTab {
    #[default]
    Objects,
    YaraRules,
    YaraMatches,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EncryptedView {
    #[default]
    Tls,
    Quic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvestigationView {
    Summary,
    Decode,
    Bytes,
    Flow,
    Strings,
    Encrypted,
    Security,
    Notes,
}

impl InvestigationView {
    pub const COUNT: usize = 8;

    pub fn label(self) -> &'static str {
        match self {
            Self::Summary => "Summary",
            Self::Decode => "Headers",
            Self::Bytes => "Bytes",
            Self::Flow => "Flow",
            Self::Strings => "Strings",
            Self::Encrypted => "Encrypted",
            Self::Security => "Security",
            Self::Notes => "Notes",
        }
    }

    pub fn from_index(index: usize) -> Self {
        match index {
            1 => Self::Decode,
            2 => Self::Bytes,
            3 => Self::Flow,
            4 => Self::Strings,
            5 => Self::Encrypted,
            6 => Self::Security,
            7 => Self::Notes,
            _ => Self::Summary,
        }
    }

    pub fn index(self) -> usize {
        match self {
            Self::Summary => 0,
            Self::Decode => 1,
            Self::Bytes => 2,
            Self::Flow => 3,
            Self::Strings => 4,
            Self::Encrypted => 5,
            Self::Security => 6,
            Self::Notes => 7,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PacketWorklist {
    pub packet_nos: Vec<u64>,
    pub active: Option<usize>,
    pub open: bool,
}

impl PacketWorklist {
    pub fn add(&mut self, packet_no: u64) -> bool {
        if let Some(index) = self.packet_nos.iter().position(|no| *no == packet_no) {
            self.active = Some(index);
            return false;
        }
        self.packet_nos.push(packet_no);
        self.active = Some(self.packet_nos.len() - 1);
        true
    }

    pub fn remove_active(&mut self) -> Option<u64> {
        let index = self.active?;
        if index >= self.packet_nos.len() { return None; }
        let removed = self.packet_nos.remove(index);
        self.active = if self.packet_nos.is_empty() {
            None
        } else {
            Some(index.min(self.packet_nos.len() - 1))
        };
        Some(removed)
    }

    pub fn active_packet_no(&self) -> Option<u64> {
        self.active.and_then(|index| self.packet_nos.get(index).copied())
    }

    pub fn next(&mut self) {
        if self.packet_nos.is_empty() { return; }
        self.active = Some(self.active.map(|index| (index + 1) % self.packet_nos.len()).unwrap_or(0));
    }

    pub fn prev(&mut self) {
        if self.packet_nos.is_empty() { return; }
        self.active = Some(self.active
            .map(|index| if index == 0 { self.packet_nos.len() - 1 } else { index - 1 })
            .unwrap_or(0));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupMode {
    Capture,
    Simulation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliAction {
    Run(StartupOptions),
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupOptions {
    pub mode: StartupMode,
    pub telemetry_listen: Option<std::net::SocketAddr>,
    pub key_log_path: Option<std::path::PathBuf>,
    pub tls_decrypt_helper_path: Option<std::path::PathBuf>,
    pub quic_decode_helper_path: Option<std::path::PathBuf>,
    pub latch_mode: LatchMode,
    pub latch_expiry_seconds: u64,
    pub protected_addresses: Vec<std::net::IpAddr>,
    pub sandbox: bool,
    pub socket_events_path: Option<std::path::PathBuf>,
    pub latch_helper_path: Option<std::path::PathBuf>,
    pub reputation_helper_path: Option<std::path::PathBuf>,
}

pub fn usage() -> &'static str {
    "Usage: packrat [OPTIONS]\n\nOptions:\n  -s, --simulation           run the built-in simulated traffic scenario\n      --key-log PATH         load NSS/SSLKEYLOGFILE TLS and QUIC secrets\n      --tls-decrypt-helper P delegate authenticated TLS record decode to helper\n      --quic-decode-helper P delegate protected QUIC/HTTP3 decode to helper\n      --socket-events PATH   import socket ownership CSV from an external helper\n      --latch-helper PATH    delegate TrafficLatch blocks to a JSON helper command\n      --reputation-helper P  delegate explicit reputation refreshes to a helper\n      --telemetry-listen A   expose /metrics and /health (example: 127.0.0.1:9477)\n      --traffic-latch MODE   monitor, preview, manual, or auto (default: monitor)\n      --latch-seconds N      automatic firewall expiry (default: 900)\n      --protect-address IP   never contain this address; may be repeated\n      --sandbox              restrict filesystem writes with Linux Landlock\n  -h, --help                 show this help"
}

pub fn parse_startup_args<I, S>(args: I) -> Result<CliAction, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|arg| arg.as_ref().to_string()).collect();
    let mut options = StartupOptions {
        mode: StartupMode::Capture,
        telemetry_listen: None,
        key_log_path: None,
        tls_decrypt_helper_path: None,
        quic_decode_helper_path: None,
        latch_mode: LatchMode::Monitor,
        latch_expiry_seconds: 900,
        protected_addresses: Vec::new(),
        sandbox: false,
        socket_events_path: None,
        latch_helper_path: None,
        reputation_helper_path: None,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-s" | "--simulation" => options.mode = StartupMode::Simulation,
            "-h" | "--help" => return Ok(CliAction::Help),
            "--telemetry-listen" => {
                index += 1;
                let value = args.get(index).ok_or("--telemetry-listen requires an address")?;
                options.telemetry_listen = Some(value.parse().map_err(|_| format!("invalid telemetry address: {value}"))?);
            }
            "--key-log" => {
                index += 1;
                let value = args.get(index).ok_or("--key-log requires a path")?;
                options.key_log_path = Some(value.into());
            }
            "--tls-decrypt-helper" => {
                index += 1;
                let value = args.get(index).ok_or("--tls-decrypt-helper requires a path")?;
                options.tls_decrypt_helper_path = Some(value.into());
            }
            "--quic-decode-helper" => {
                index += 1;
                let value = args.get(index).ok_or("--quic-decode-helper requires a path")?;
                options.quic_decode_helper_path = Some(value.into());
            }
            "--socket-events" => {
                index += 1;
                let value = args.get(index).ok_or("--socket-events requires a path")?;
                options.socket_events_path = Some(value.into());
            }
            "--latch-helper" => {
                index += 1;
                let value = args.get(index).ok_or("--latch-helper requires a path")?;
                options.latch_helper_path = Some(value.into());
            }
            "--reputation-helper" => {
                index += 1;
                let value = args.get(index).ok_or("--reputation-helper requires a path")?;
                options.reputation_helper_path = Some(value.into());
            }
            "--traffic-latch" => {
                index += 1;
                let value = args.get(index).ok_or("--traffic-latch requires a mode")?;
                options.latch_mode = value.parse()?;
            }
            "--latch-seconds" => {
                index += 1;
                let value = args.get(index).ok_or("--latch-seconds requires a value")?;
                options.latch_expiry_seconds = value.parse::<u64>()
                    .map_err(|_| format!("invalid latch expiry: {value}"))?;
                if !(10..=86_400).contains(&options.latch_expiry_seconds) {
                    return Err("latch expiry must be between 10 and 86400 seconds".into());
                }
            }
            "--protect-address" => {
                index += 1;
                let value = args.get(index).ok_or("--protect-address requires an IP")?;
                options.protected_addresses.push(value.parse()
                    .map_err(|_| format!("invalid protected address: {value}"))?);
            }
            "--sandbox" => options.sandbox = true,
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
        index += 1;
    }
    Ok(CliAction::Run(options))
}

fn list_interfaces(include_simulated: bool) -> Vec<String> {
    let mut ifaces = Vec::new();
    if include_simulated {
        ifaces.push("simulated".to_string());
    }
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        let mut sys: Vec<String> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        sys.sort();
        ifaces.extend(sys);
    }
    ifaces
}

pub struct App {
    pub active_tab: Tab,
    pub packets: VecDeque<Packet>,
    pub filtered: Vec<usize>,
    pub selected: Option<usize>,
    pub total_bytes: u64,
    pub packet_counter: u64,
    pub capturing: bool,
    capture_handle: Option<JoinHandle<()>>,
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
    pub pcap_path: String,
    pcap_writer: Option<PcapWriter>,
    pub show_help: bool,
    pub dissectors: Vec<DissectorDef>,
    pub strings_search_active: bool,
    pub strings_selected: Option<usize>,
    pub strings_scroll: usize,
    pub flow_tracker: FlowTracker,
    pub flows_selected: Option<usize>,
    pub flows_sort: FlowSort,
    pub stream_overlay: Option<(String, Vec<(bool, Vec<u8>)>)>,
    pub lua_plugins: PluginManager,
    pub lua_reload_msg: Option<String>,
    pub craft: CraftState,
    pub traceroute: TracerouteState,
    pub security: SecurityEngine,
    pub credentials: Vec<CredentialHit>,
    pub scan: ScanState,
    pub replay: ReplayState,
    pub security_tab: SecuritySubTab,
    pub security_scroll: usize,
    pub scanner_scroll: usize,
    pub replay_editing:       bool,
    /// Whether the PCAP instant-import path input is active.
    pub pcap_import_editing:  bool,
    pub pcap_import_path:     String,
    pub scan_editing: bool,
    // ─── Phase 1–4 analysis state ──────────────────────────────────────────────
    pub hosts:           HostInventory,
    pub tag_store:       TagStore,
    pub notebook:        Notebook,
    pub streams:         StreamAssembler,
    pub timeline:        ProtocolTimelines,
    pub tls_tracker:     TlsTracker,
    pub quic_scope:      QuicScope,
    pub vlan_intel:      VlanIntel,
    pub ioc_engine:      IocEngine,
    pub rule_engine:     RuleEngine,
    pub incidents:       IncidentStore,
    pub evidence_vault:  EvidenceVault,
    pub telemetry:       TelemetryHub,
    pub socket_scope:    SocketScope,
    pub route_ledger:    RouteLedger,
    pub traffic_latch:   TrafficLatch,
    pub latch_helper_path: Option<std::path::PathBuf>,
    pub wire_pulse:      WirePulse,
    pub net_registry:    NetRegistry,
    pub reputation_helper_path: Option<std::path::PathBuf>,
    /// Visible only while an unreviewed critical incident needs attention.
    pub alert_overlay_open: bool,
    pub carver:          Carver,
    pub carved_objects:  Vec<CarvedObject>,
    pub workbench:       ProtocolWorkbench,
    pub diff_engine:      DiffEngine,
    pub diff_scroll:      usize,
    /// Cloned packet snapshot used as baseline for differential analysis.
    pub diff_baseline:    Vec<crate::net::packet::Packet>,
    pub job_queue:       JobQueue,
    pub display_filter:  DisplayFilter,
    // Notebook UI state
    pub notebook_scroll:      usize,
    pub notebook_input:       String,
    pub notebook_editing:     bool,
    pub notebook_searching:   bool,
    pub notebook_search:      String,
    // Hosts UI state
    pub hosts_scroll:    usize,
    pub hosts_search:    String,
    pub hosts_searching: bool,
    pub hosts_tagging:   bool,
    pub hosts_tag_input: String,
    // TLS UI state
    pub tls_scroll:      usize,
    pub tls_selected:    usize,
    pub encrypted_view:  EncryptedView,
    // Objects UI state
    pub objects_scroll:       usize,
    pub objects_subtab:       ObjectsSubTab,
    pub yara_rules_scroll:    usize,
    pub yara_matches_scroll:  usize,
    // YARA engine
    pub yara_engine:          YaraEngine,
    /// High-water mark: next carved object index to scan.
    pub yara_scan_cursor:         usize,
    // Rules UI state
    pub rules_scroll:    usize,
    // ─── Operator graph ────────────────────────────────────────────────────────
    pub operator_graph:  OperatorGraphEngine,
    pub graph_ui:        GraphUiState,
    /// Tick counter used to throttle graph recomputation.
    graph_tick_counter:  u32,
    // ─── Global command palette ────────────────────────────────────────────────
    pub search_open:     bool,
    pub search_query:    String,
    pub search_results:  Vec<SearchResult>,
    pub search_selected: usize,
    // ─── Protocol Autopsy overlay ──────────────────────────────────────────────
    pub autopsy_state:   Option<AutopsyState>,
    // ─── Theme ────────────────────────────────────────────────────────────────
    /// Name of the active built-in theme.
    pub selected_theme_name:  String,
    /// Whether the theme picker overlay is shown.
    pub theme_picker_open:    bool,
    pub theme_picker_cursor:  usize,
    /// Workspace-local view drawer state.
    pub view_menu_open:       bool,
    pub view_menu_cursor:     usize,
    pub worklist:             PacketWorklist,
    pub investigation_view:   InvestigationView,
    pub investigation_scroll: usize,
    pub header_cursor:        usize,
    pub header_searching:     bool,
    pub header_search:        String,
    pub settings_open:        bool,
    pub settings_cursor:      usize,
    // ─── Project management ────────────────────────────────────────────────────
    /// Name of the currently open project (None = ad-hoc workspace).
    pub current_project_name: Option<String>,
    /// Filesystem path of the currently open project file.
    pub current_project_path: Option<String>,
    /// True when there are unsaved changes since the last save.
    pub project_dirty:        bool,
    /// Whether the project manager overlay is shown.
    pub project_manager_open: bool,
    pub project_manager:      ProjectManagerState,
    // ─── Status / feedback message (transient, cleared after a few ticks) ─────
    pub status_msg:      Option<String>,
    status_msg_ticks:    u8,
}

impl App {
    pub fn new(packet_tx: Sender<Packet>) -> Self {
        Self::new_with_mode(packet_tx, StartupMode::Capture)
    }

    pub fn new_with_mode(packet_tx: Sender<Packet>, startup_mode: StartupMode) -> Self {
        let iface_list = list_interfaces(startup_mode == StartupMode::Simulation);
        let selected_iface = iface_list.first().cloned().unwrap_or_default();
        let mut app = Self {
            active_tab: Tab::Packets,
            packets: VecDeque::new(),
            filtered: Vec::new(),
            selected: None,
            total_bytes: 0,
            packet_counter: 0,
            capturing: false,
            capture_handle: None,
            packet_tx,
            picking_iface: startup_mode != StartupMode::Simulation,
            iface_list,
            iface_sel: 0,
            selected_iface,
            filter: PacketFilter::default(),
            rate_history: vec![0u32; 60],
            rate_this_sec: 0,
            rate_tick: 0,
            dyn_log: Vec::new(),
            dyn_scroll: 0,
            analysis_section: 0,
            strings_filter: String::new(),
            _hex_scroll: 0,
            recording: false,
            pcap_path: String::new(),
            pcap_writer: None,
            show_help: false,
            dissectors: crate::dissector::load(),
            strings_search_active: false,
            strings_selected: None,
            strings_scroll: 0,
            flow_tracker: FlowTracker::new(),
            flows_selected: None,
            flows_sort: FlowSort::Bytes,
            stream_overlay: None,
            lua_plugins: {
                let mut pm = PluginManager::new();
                pm.reload();
                pm
            },
            lua_reload_msg: None,
            craft: CraftState::default(),
            traceroute: TracerouteState::default(),
            security: SecurityEngine::default(),
            credentials: Vec::new(),
            scan: ScanState::new(),
            replay: ReplayState::default(),
            security_tab: SecuritySubTab::Ids,
            security_scroll: 0,
            scanner_scroll: 0,
            replay_editing:      false,
            pcap_import_editing: false,
            pcap_import_path:    String::new(),
            scan_editing: false,
            hosts:            HostInventory::default(),
            tag_store:        TagStore::default(),
            notebook:         Notebook::default(),
            streams:          StreamAssembler::default(),
            timeline:         ProtocolTimelines::default(),
            tls_tracker:      TlsTracker::default(),
            quic_scope:       QuicScope::default(),
            vlan_intel:       VlanIntel::default(),
            ioc_engine:       {
                let mut e = IocEngine::default();
                e.load_from_dir();
                e
            },
            rule_engine:      {
                let mut e = RuleEngine::default();
                e.load_from_dir();
                e
            },
            incidents:        IncidentStore::default(),
            evidence_vault:   EvidenceVault::default(),
            telemetry:        TelemetryHub::default(),
            socket_scope:     SocketScope::default(),
            route_ledger:     RouteLedger::default(),
            traffic_latch:    TrafficLatch::default(),
            latch_helper_path: None,
            wire_pulse:       WirePulse::default(),
            net_registry:     NetRegistry::default(),
            reputation_helper_path: None,
            alert_overlay_open: false,
            carver:           Carver::default(),
            carved_objects:   Vec::new(),
            workbench:        ProtocolWorkbench::default(),
            diff_engine:      DiffEngine::default(),
            diff_scroll:      0,
            diff_baseline:    Vec::new(),
            job_queue:        JobQueue::default(),
            display_filter:   DisplayFilter::default(),
            notebook_scroll:      0,
            notebook_input:       String::new(),
            notebook_editing:     false,
            notebook_searching:   false,
            notebook_search:      String::new(),
            hosts_scroll:     0,
            hosts_search:     String::new(),
            hosts_searching:  false,
            hosts_tagging:    false,
            hosts_tag_input:  String::new(),
            tls_scroll:            0,
            tls_selected:          0,
            encrypted_view:        EncryptedView::Tls,
            objects_scroll:        0,
            objects_subtab:        ObjectsSubTab::Objects,
            yara_rules_scroll:     0,
            yara_matches_scroll:   0,
            yara_engine:           YaraEngine::new(),
            yara_scan_cursor:      0,
            rules_scroll:          0,
            operator_graph:   OperatorGraphEngine::default(),
            graph_ui:         GraphUiState::default(),
            graph_tick_counter: 0,
            search_open:     false,
            search_query:    String::new(),
            search_results:  Vec::new(),
            search_selected: 0,
            autopsy_state:    None,
            selected_theme_name:  theme_store::load_theme_name(),
            theme_picker_open:    false,
            theme_picker_cursor:  0,
            view_menu_open:       false,
            view_menu_cursor:     0,
            worklist:             PacketWorklist::default(),
            investigation_view:   InvestigationView::Summary,
            investigation_scroll: 0,
            header_cursor:        0,
            header_searching:     false,
            header_search:        String::new(),
            settings_open:        false,
            settings_cursor:      0,
            current_project_name: None,
            current_project_path: None,
            project_dirty:        false,
            project_manager_open: false,
            project_manager:      ProjectManagerState::default(),
            status_msg:       None,
            status_msg_ticks: 0,
        };

        if startup_mode == StartupMode::Simulation {
            app.confirm_iface();
        }

        app
    }

    /// Reload JSON rules from ~/.config/packrat/rules/ and show status.
    pub fn reload_rules(&mut self) {
        self.rule_engine.rules.clear();
        let errs = self.rule_engine.load_from_dir();
        let count = self.rule_engine.rules.len();
        if errs.is_empty() {
            self.set_status(format!("Rules: {count} rules loaded"));
        } else {
            self.set_status(format!("Rules: {count} rules, {} error(s)", errs.len()));
        }
    }

    /// Load IOC feeds from ~/.config/packrat/ioc/ and show status.
    pub fn reload_ioc_feeds(&mut self) {
        let errs = self.ioc_engine.load_from_dir();
        let count = self.ioc_engine.ioc_count();
        if errs.is_empty() {
            self.set_status(format!("IOC: {count} indicators loaded"));
        } else {
            self.set_status(format!("IOC: {count} indicators, {} error(s)", errs.len()));
        }
    }

    /// Load a PCAP file and ingest all packets instantly into the live capture pipeline.
    /// This is suitable for offline analysis; does not affect replay state.
    pub fn load_pcap_instant(&mut self, path: &str) {
        let path_buf = std::path::PathBuf::from(path.trim());
        match crate::pcap_replay::read_pcap(&path_buf) {
            Ok(packets) => {
                let count = packets.len();
                for pkt in packets {
                    self.ingest_packet_inner(pkt);
                }
                self.set_status(format!("Loaded {} packets from {}", count, path_buf.file_name().and_then(|n| n.to_str()).unwrap_or(path)));
            }
            Err(e) => {
                self.set_status(format!("PCAP load error: {e}"));
            }
        }
    }

    /// Snapshot current live packets as diff baseline (set A).
    pub fn diff_snapshot_baseline(&mut self) {
        let pkts: Vec<_> = self.packets.iter().cloned().collect();
        self.diff_engine.load_a(&pkts);
        self.diff_baseline = pkts.clone();
        self.set_status(format!("Diff baseline set: {} packets", pkts.len()));
    }

    /// Compute diff between baseline (A) and current live packets (B), then jump to Diff tab.
    pub fn diff_compute(&mut self) {
        if self.diff_baseline.is_empty() {
            self.set_status("No baseline — press B first".to_string());
            return;
        }
        let current: Vec<_> = self.packets.iter().cloned().collect();
        self.diff_engine.load_b(&current);
        self.diff_engine.compute(&self.diff_baseline.clone(), &current);
        self.active_tab = crate::tabs::Tab::Diff;
        self.diff_scroll = 0;
        self.set_status(format!("Diff: {} baseline vs {} current packets",
            self.diff_baseline.len(), current.len()));
    }

    /// Apply the current `hosts_tag_input` as a tag to the host at `hosts_scroll`.
    pub fn apply_host_tag(&mut self) {
        let tag = self.hosts_tag_input.trim().to_string();
        if tag.is_empty() { return; }
        let hosts = self.hosts.all();
        if let Some(h) = hosts.get(self.hosts_scroll) {
            let ip = h.ip.clone();
            if let Some(host) = self.hosts.get_mut(&ip) {
                host.tags.insert(tag.clone());
            }
            self.set_status(format!("Tagged {ip} as \"{tag}\""));
        }
    }

    /// Remove a tag from the host at `hosts_scroll` (removes the first tag, alphabetically).
    pub fn remove_host_tag(&mut self) {
        let hosts = self.hosts.all();
        if let Some(h) = hosts.get(self.hosts_scroll) {
            let ip = h.ip.clone();
            let tag = h.tags.iter().min().cloned();
            if let (Some(host), Some(t)) = (self.hosts.get_mut(&ip), tag) {
                host.tags.remove(&t);
                self.set_status(format!("Removed tag \"{t}\" from {ip}"));
            }
        }
    }

    /// Set a transient status message shown in the status bar for ~3 seconds.
    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_msg = Some(msg.into());
        self.status_msg_ticks = 30; // 30 ticks ≈ 3s at 10Hz
    }

    // ─── Scenario seeding (simulated mode) ────────────────────────────────────

    /// Seed the app with the correlated investigation scenario so all tabs
    /// have meaningful content immediately in simulated/demo mode.
    pub fn seed_scenario(&mut self) {
        use crate::sim::scenario;

        // Ingest all scenario packets
        for pkt in scenario::build() {
            self.ingest_packet_inner(pkt);
        }

        // Seed IOC hits for the C2 IP
        for ip in scenario::ioc_ips() {
            self.ioc_engine.load_ioc(crate::analysis::ioc::Ioc {
                kind:        crate::analysis::ioc::IocKind::Ip,
                value:       ip.into(),
                description: "Operation Quiet Beacon C2 infrastructure".into(),
                source:      "scenario".into(),
            });
        }
        // Re-scan packets against IOCs now that they're loaded
        let pkts: Vec<_> = self.packets.iter().cloned().collect();
        for pkt in &pkts {
            self.ioc_engine.check_packet(pkt);
        }

        // Seed notebook notes
        for (text, ev_str) in scenario::notebook_notes() {
            let ev = ev_str.map(|s| crate::model::evidence::EvidenceRef::Packet(
                crate::model::evidence::PacketRef(
                    s.trim_start_matches("pkt#").parse().unwrap_or(0)
                )
            ));
            self.notebook.add(text, ev);
        }

        // Seed host tags
        for (ip, tags) in scenario::host_tags() {
            for tag in tags {
                self.hosts.seed_tags(ip, std::iter::once(tag.to_string()));
            }
        }

        // ── TLS Analysis tab ─────────────────────────────────────────────────
        for session in scenario::tls_sessions() {
            self.tls_tracker.insert(session);
        }

        // ── Security tab ─────────────────────────────────────────────────────
        let sec = scenario::security_seed();
        self.security.ids_alerts.extend(sec.ids_alerts);
        self.security.arp_anomalies.extend(sec.arp_anomalies);
        for g in sec.os_guesses {
            self.security.os_guesses.push(g);
        }
        self.security.vuln_hits.extend(sec.vuln_hits);
        self.security.brute_force.extend(sec.brute_force);
        self.security.http_records.extend(sec.http_records);
        self.security.tls_weaknesses.extend(sec.tls_weaknesses);
        self.security.dns_suspects.extend(sec.dns_suspects);

        // ── Credentials sub-tab ──────────────────────────────────────────────
        self.credentials.extend(scenario::credentials());
        self.security.cred_hit_count = self.credentials.len();

        // ── Objects tab ──────────────────────────────────────────────────────
        self.carved_objects.extend(scenario::carved_objects());

        // ── Rules tab ────────────────────────────────────────────────────────
        for (rule, _hits) in scenario::rules() {
            self.rule_engine.add_rule(rule);
        }
        // Fire rules against the already-ingested packets so hit counts are live
        let pkts2: Vec<_> = self.packets.iter().cloned().collect();
        for pkt in &pkts2 {
            self.rule_engine.evaluate(pkt);
        }

        self.set_status("Scenario loaded: Operation Quiet Beacon — all tabs populated");
    }

    // ─── Test helpers ────────────────────────────────────────────────────────

    /// Construct an App pre-configured for tests (no terminal, no capture).
    pub fn new_for_test() -> App {
        let (tx, _rx) = tokio::sync::mpsc::channel(1024);
        let mut app = App::new(tx);
        app.picking_iface = false;
        app.selected_iface = "simulated".to_string();
        app
    }

    /// Construct an App seeded with the full correlated scenario dataset.
    pub fn new_with_scenario() -> App {
        let mut app = Self::new_for_test();
        app.seed_scenario();
        app
    }

    // ─── Theme ────────────────────────────────────────────────────────────────

    /// Apply a theme by name, set it as current, and persist the choice.
    pub fn apply_theme(&mut self, name: &str) {
        self.selected_theme_name = name.to_string();
        let _ = theme_store::save_theme_name(name);
    }

    // ─── Project save / load ──────────────────────────────────────────────────

    /// Open the project manager overlay and refresh the recent list.
    pub fn open_project_manager(&mut self) {
        self.project_manager_open = true;
        self.project_manager.recent = project_store::recent_projects();
        self.project_manager.status = None;
    }

    /// Snapshot the current analysis state into a `ProjectState`.
    fn snapshot_project(&self, name: &str, mode: ProjectSaveMode) -> crate::model::project::ProjectState {
        use crate::model::project::ProjectState;
        use crate::storage::case_bundle::ObjectEntry;
        let mut state = ProjectState::new(name, mode);
        // Clone notebook
        state.notebook = self.notebook.clone();
        // Clone tag store
        state.tag_store = self.tag_store.clone();
        // Active filter text
        state.active_filter = self.filter.input.clone();
        // Host tags: ip → sorted vec
        for host in self.hosts.all() {
            if !host.tags.is_empty() {
                let mut tags: Vec<String> = host.tags.iter().cloned().collect();
                tags.sort();
                state.host_tags.insert(host.ip.clone(), tags);
            }
        }
        // Carved object metadata
        state.carved_objects = self.carved_objects.iter().map(ObjectEntry::from).collect();
        state
    }

    /// Save the current project to `path`.  Marks the workspace clean.
    pub fn save_project(&mut self, path: &str, name: &str, mode: ProjectSaveMode) {
        let state = self.snapshot_project(name, mode.clone());
        let p = std::path::Path::new(path);
        match project_store::save(&state, p) {
            Ok(()) => {
                let _ = project_store::add_to_recent(
                    name, p,
                    state.metadata.description.as_deref(),
                    mode,
                );
                self.current_project_name = Some(name.to_string());
                self.current_project_path = Some(path.to_string());
                self.project_dirty = false;
                self.set_status(format!("Project saved: {name}"));
            }
            Err(e) => {
                self.set_status(format!("Save failed: {e}"));
            }
        }
    }

    /// Load a project from `path`, restoring notebook, tags, filter, host tags.
    pub fn load_project(&mut self, path: &str) {
        match project_store::load(std::path::Path::new(path)) {
            Ok(state) => {
                let name = state.metadata.name.clone();
                let mode = state.metadata.save_mode.clone();
                // Restore notebook
                self.notebook = state.notebook;
                // Restore tag store
                self.tag_store = state.tag_store;
                // Restore active filter
                if !state.active_filter.is_empty() {
                    self.filter.input = state.active_filter;
                    self.rebuild_filtered();
                }
                // Restore host tags (seeds entries; traffic will fill the rest)
                for (ip, tags) in state.host_tags {
                    self.hosts.seed_tags(&ip, tags);
                }
                // Update project tracking state
                let _ = project_store::add_to_recent(
                    &name, std::path::Path::new(path),
                    state.metadata.description.as_deref(),
                    mode,
                );
                self.current_project_name = Some(name.clone());
                self.current_project_path = Some(path.to_string());
                self.project_dirty = false;
                self.project_manager_open = false;
                self.set_status(format!("Project loaded: {name}"));
            }
            Err(e) => {
                self.project_manager.status = Some(format!("Load failed: {e}"));
            }
        }
    }

    /// Quick-save the current project if one is open; otherwise open Save As dialog.
    pub fn quick_save_project(&mut self) {
        if let (Some(path), Some(name)) = (
            self.current_project_path.clone(),
            self.current_project_name.clone(),
        ) {
            self.save_project(&path, &name, ProjectSaveMode::Lightweight);
        } else {
            // No active project — open manager on New tab
            self.open_project_manager();
            self.project_manager.tab = crate::ui::project_manager::PmTab::New;
        }
    }

    /// Export a full case bundle JSON to a timestamped file and set a status message.
    pub fn export_case_bundle(&mut self) {
        match crate::analysis::case_export::export_auto(self) {
            Ok(path) => self.set_status(format!("Case bundle written: {path}")),
            Err(e)   => self.set_status(format!("Export failed: {e}")),
        }
    }

    /// Open the Protocol Autopsy overlay for the currently selected packet.
    pub fn open_autopsy(&mut self) {
        let pkt = match self.selected_packet() {
            Some(p) => p.clone(),
            None => return,
        };

        let tree = self.dissect_packet(&pkt);

        // Build stream preview from reassembled data for this flow
        let stream_key = crate::analysis::stream::StreamKey::from_packet(&pkt);
        let stream_preview = if let Some(key) = stream_key {
            match self.streams.get(&key.id()) {
                Some(stream) => {
                    let mut lines: Vec<(bool, String)> = Vec::new();
                    // Client data
                    for chunk in stream.client_data.chunks(72) {
                        lines.push((true, printable_line(chunk)));
                    }
                    // Server data
                    for chunk in stream.server_data.chunks(72) {
                        lines.push((false, printable_line(chunk)));
                    }
                    lines
                }
                None => Vec::new(),
            }
        } else {
            Vec::new()
        };

        self.autopsy_state = Some(AutopsyState::new(tree, stream_preview));
    }

    /// Close the Protocol Autopsy overlay.
    pub fn close_autopsy(&mut self) {
        self.autopsy_state = None;
    }

    /// Reload YARA rules from ~/.config/packrat/yara/ and clear existing results.
    pub fn reload_yara_rules(&mut self) {
        self.yara_engine.reload();
        self.yara_engine.clear_results();
        self.yara_scan_cursor = 0;
    }

    /// Force a full re-scan of all carved objects with current rules.
    pub fn yara_force_rescan(&mut self) {
        self.yara_engine.clear_results();
        self.yara_scan_cursor = 0;
        self.yara_scan_new_objects();
    }

    /// Incrementally scan carved objects that haven't been scanned yet.
    /// Called from tick() to spread work across frames.  Scans at most 4
    /// objects per tick so the UI never blocks.
    pub fn yara_scan_new_objects(&mut self) {
        if self.yara_engine.rules.is_empty() { return; }
        let start = self.yara_scan_cursor;
        let end = (start + 4).min(self.carved_objects.len());
        if start >= end { return; }

        // Collect the minimum data needed before any mutable borrow of self.
        const SCAN_CAP: usize = 1_048_576;
        let batch: Vec<(u64, String, Vec<u8>)> = self.carved_objects[start..end]
            .iter()
            .map(|obj| {
                let cap = obj.data.len().min(SCAN_CAP);
                (obj.id, obj.kind.clone(), obj.data[..cap].to_vec())
            })
            .collect();

        for (rel_idx, (id, kind, data)) in batch.into_iter().enumerate() {
            let result = self.yara_engine.scan_target(
                &data, id, "object", &format!("#{} {}", id, kind),
            );
            if !result.matches.is_empty() {
                let rule_names = result.rule_names();
                self.carved_objects[start + rel_idx].yara_hits = rule_names;
                self.yara_engine.results.push(result);
            }
        }
        self.yara_scan_cursor = end;
    }

    /// Carve embedded files from all reassembled TCP streams.
    pub fn carve_from_streams(&mut self) {
        let streams: Vec<(String, Vec<u8>, Vec<u8>)> = self.streams.all()
            .iter()
            .map(|s| (s.key.id(), s.client_data.clone(), s.server_data.clone()))
            .collect();

        for (id, client_data, server_data) in streams {
            let source = id.clone();
            if !client_data.is_empty() {
                let new_objs = self.carver.carve(&client_data, &format!("{source}→"));
                self.carved_objects.extend(new_objs);
            }
            if !server_data.is_empty() {
                let new_objs = self.carver.carve(&server_data, &format!("{source}←"));
                self.carved_objects.extend(new_objs);
            }
        }
    }

    /// Open the command palette and run an initial empty search.
    pub fn open_search(&mut self) {
        self.search_open = true;
        self.search_query.clear();
        self.search_selected = 0;
        self.run_search();
    }

    /// Close the command palette without navigating.
    pub fn close_search(&mut self) {
        self.search_open = false;
    }

    /// Execute search across all data sources and populate `search_results`.
    /// Called on every keystroke while the palette is open.
    pub fn run_search(&mut self) {
        let q = self.search_query.to_lowercase();
        let mut results: Vec<SearchResult> = Vec::new();

        // ── Packets ──────────────────────────────────────────────────────────
        for (idx, pkt) in self.packets.iter().enumerate().take(500) {
            let label = format!("#{} {} → {} [{}]", pkt.no, pkt.src, pkt.dst, pkt.protocol);
            let detail = pkt.info.clone();
            let haystack = format!("{} {} {} {}", label, detail,
                pkt.src_port.map_or_else(String::new, |p| p.to_string()),
                pkt.dst_port.map_or_else(String::new, |p| p.to_string()))
                .to_lowercase();
            if q.is_empty() || haystack.contains(&q) {
                results.push(SearchResult {
                    source: "Packet", label, detail,
                    jump_tab: Tab::Packets, scroll: idx,
                });
                if results.len() >= 20 { break; }
            }
        }

        // ── Hosts ─────────────────────────────────────────────────────────────
        let host_list: Vec<_> = self.hosts.all().into_iter().enumerate().collect();
        for (idx, host) in host_list {
            let label = host.ip.clone();
            let detail = format!("pkts:{} bytes:{}", host.pkts_out + host.pkts_in,
                host.bytes_out + host.bytes_in);
            let haystack = format!("{} {}", label, detail).to_lowercase();
            if q.is_empty() || haystack.contains(&q) {
                results.push(SearchResult {
                    source: "Host", label, detail,
                    jump_tab: Tab::Hosts, scroll: idx,
                });
                if results.iter().filter(|r| r.source == "Host").count() >= 10 { break; }
            }
        }

        // ── IOC hits ──────────────────────────────────────────────────────────
        for (idx, hit) in self.ioc_engine.hits.iter().enumerate() {
            let label = format!("{} {}", hit.ioc.kind, hit.ioc.value);
            let detail = hit.context.clone();
            let haystack = format!("{} {}", label, detail).to_lowercase();
            if q.is_empty() || haystack.contains(&q) {
                results.push(SearchResult {
                    source: "IOC Hit", label, detail,
                    jump_tab: Tab::Security, scroll: idx,
                });
                if results.iter().filter(|r| r.source == "IOC Hit").count() >= 10 { break; }
            }
        }

        // ── Rule hits ─────────────────────────────────────────────────────────
        for (idx, hit) in self.rule_engine.hits.iter().enumerate() {
            let label = hit.rule_name.clone();
            let detail = hit.message.clone();
            let haystack = format!("{} {}", label, detail).to_lowercase();
            if q.is_empty() || haystack.contains(&q) {
                results.push(SearchResult {
                    source: "Rule Hit", label, detail,
                    jump_tab: Tab::Rules, scroll: idx,
                });
                if results.iter().filter(|r| r.source == "Rule Hit").count() >= 10 { break; }
            }
        }

        // ── YARA matches ──────────────────────────────────────────────────────
        for (idx, result) in self.yara_engine.results.iter().enumerate() {
            let label = result.target_label.clone();
            let detail = result.rule_names().join(", ");
            let haystack = format!("{} {}", label, detail).to_lowercase();
            if q.is_empty() || haystack.contains(&q) {
                results.push(SearchResult {
                    source: "YARA",
                    label,
                    detail,
                    jump_tab: Tab::Objects,
                    scroll: idx,
                });
                if results.iter().filter(|r| r.source == "YARA").count() >= 10 { break; }
            }
        }

        // ── Carved objects ────────────────────────────────────────────────────
        for (idx, obj) in self.carved_objects.iter().enumerate() {
            let label = format!("#{} {}", obj.id, obj.kind);
            let detail = obj.source.clone();
            let haystack = format!("{} {} {}", label, detail, obj.sha256).to_lowercase();
            if q.is_empty() || haystack.contains(&q) {
                results.push(SearchResult {
                    source: "Object", label, detail,
                    jump_tab: Tab::Objects, scroll: idx,
                });
                if results.iter().filter(|r| r.source == "Object").count() >= 10 { break; }
            }
        }

        self.search_results = results;
        self.search_selected = self.search_selected.min(
            self.search_results.len().saturating_sub(1)
        );
    }

    /// Apply the currently selected search result (navigate to it).
    pub fn search_jump(&mut self) {
        if let Some(result) = self.search_results.get(self.search_selected).cloned() {
            self.active_tab = result.jump_tab.clone();
            // Apply scroll hints depending on destination
            match result.jump_tab {
                Tab::Packets  => { self.selected = Some(result.scroll); }
                Tab::Hosts    => { self.hosts_scroll = result.scroll; }
                Tab::Rules    => { self.rules_scroll = result.scroll; }
                Tab::Objects  => { self.objects_scroll = result.scroll; }
                Tab::Security => { self.security_scroll = result.scroll; }
                _ => {}
            }
        }
        self.close_search();
    }

    /// Hot-reload all Lua plugins from ~/.config/packrat/plugins/
    pub fn reload_lua_plugins(&mut self) {
        self.lua_plugins.reload();
        let n = self.lua_plugins.plugin_count();
        let p = self.lua_plugins.proto_count();
        let errs = self.lua_plugins.error_log.len();
        if errs > 0 {
            self.lua_reload_msg = Some(format!(
                "Lua: {n} files, {p} dissectors — {} error(s)", errs
            ));
        } else {
            self.lua_reload_msg = Some(format!(
                "Lua: {n} files, {p} dissectors loaded"
            ));
        }
    }

    /// Navigate the strings list (only when capture is stopped).
    pub fn strings_move_down(&mut self, list_len: usize) {
        if self.capturing || list_len == 0 { return; }
        let cur = self.strings_selected.unwrap_or(0);
        let next = (cur + 1).min(list_len.saturating_sub(1));
        self.strings_selected = Some(next);
        // strings_scroll is a scroll hint used by the draw function.
        // We advance it by 1 each time we go past the current view to
        // produce smooth scrolling (draw clamps this to selection bounds).
        if next > self.strings_scroll { self.strings_scroll = next; }
    }

    pub fn strings_move_up(&mut self) {
        if self.capturing { return; }
        let cur = self.strings_selected.unwrap_or(0);
        let prev = cur.saturating_sub(1);
        self.strings_selected = Some(prev);
        if prev < self.strings_scroll { self.strings_scroll = prev; }
    }

    pub fn strings_select(&mut self) {
        // Enter just confirms — selection is already set by j/k.
        // If nothing is selected yet, select the first item.
        if self.strings_selected.is_none() {
            self.strings_selected = Some(0);
        }
    }

    pub fn strings_deselect(&mut self) {
        self.strings_selected = None;
    }

    /// Count extracted strings (after filter) for navigation bounds.
    /// Mirrors the extraction logic in strings.rs but just counts.
    pub fn strings_list_len(&self) -> usize {
        const MIN_LEN: usize = 4;
        let mut count = 0usize;
        for pkt in self.packets.iter().take(500) {
            let mut in_run = false;
            let mut run_start = 0usize;
            for (i, &b) in pkt.bytes.iter().enumerate() {
                if b >= 32 && b < 127 {
                    if !in_run { run_start = i; in_run = true; }
                } else if in_run {
                    in_run = false;
                    if i - run_start >= MIN_LEN { count += 1; }
                }
            }
            if in_run && pkt.bytes.len() - run_start >= MIN_LEN { count += 1; }
        }
        // Apply filter if active
        if self.strings_filter.is_empty() {
            count
        } else {
            // Re-extract to filter — acceptable since this only runs on keypress
            let q = self.strings_filter.to_lowercase();
            let mut filt_count = 0usize;
            for pkt in self.packets.iter().take(500) {
                let bytes = &pkt.bytes;
                let mut in_run = false;
                let mut run_start = 0usize;
                for (i, &b) in bytes.iter().enumerate() {
                    if b >= 32 && b < 127 {
                        if !in_run { run_start = i; in_run = true; }
                    } else if in_run {
                        in_run = false;
                        if i - run_start >= MIN_LEN {
                            let val = String::from_utf8_lossy(&bytes[run_start..i]);
                            if val.to_lowercase().contains(&q) { filt_count += 1; }
                        }
                    }
                }
                if in_run && pkt.bytes.len() - run_start >= MIN_LEN {
                    let val = String::from_utf8_lossy(&pkt.bytes[run_start..]);
                    if val.to_lowercase().contains(&q) { filt_count += 1; }
                }
            }
            filt_count
        }
    }

    /// Look up a packet by its frame number (pkt.no).
    pub fn packet_by_no(&self, no: u64) -> Option<&Packet> {
        self.packets.iter().find(|p| p.no == no)
    }

    /// Build the protocol dissection tree for `pkt`, then apply any custom
    /// dissectors loaded from ~/.config/packrat/dissectors/.
    pub fn dissect_packet(&self, pkt: &Packet) -> Vec<TreeSection> {
        let mut sections = crate::net::tree::build_tree(pkt, self.selected_iface == "simulated");
        crate::dissector::apply(&self.dissectors, pkt, &mut sections);
        self.lua_plugins.apply(pkt, &mut sections);
        sections
    }

    pub fn iface_down(&mut self) {
        if self.iface_sel + 1 < self.iface_list.len() { self.iface_sel += 1; }
    }

    pub fn iface_up(&mut self) { self.iface_sel = self.iface_sel.saturating_sub(1); }

    pub fn confirm_iface(&mut self) {
        if self.iface_list.is_empty() {
            self.picking_iface = false;
            self.capturing = false;
            self.set_status("No capture interfaces found".to_string());
            return;
        }

        self.selected_iface = self.iface_list[self.iface_sel].clone();
        self.picking_iface = false;
        self.abort_capture();

        // Clear all analysis state so simulated data cannot bleed into real captures
        // and vice-versa. clear_packets() sets capturing=false; we restore it below.
        self.clear_packets();

        if self.selected_iface == "simulated" {
            self.seed_scenario();
            self.capture_handle = Some(SimulatedCapture.run(self.packet_tx.clone()));
            self.capturing = true;
        } else {
            #[cfg(feature = "real-capture")]
            {
                use crate::capture::live::LiveCapture;
                let source = LiveCapture { iface: self.selected_iface.clone(), filter: None };
                self.capture_handle = Some(source.run(self.packet_tx.clone()));
                self.capturing = true;
            }
            #[cfg(not(feature = "real-capture"))]
            { self.capturing = false; }
        }
    }

    pub fn switch_interface(&mut self) {
        self.abort_capture();
        self.picking_iface = true;
        self.capturing = false;
    }

    fn abort_capture(&mut self) {
        if let Some(handle) = self.capture_handle.take() { handle.abort(); }
    }

    pub fn ingest_packet(&mut self, pkt: Packet) {
        if !self.capturing { return; }
        self.ingest_packet_inner(pkt);
    }

    /// Inject a packet regardless of capturing state (used by packet crafter).
    pub fn inject_packet(&mut self, pkt: Packet) {
        self.ingest_packet_inner(pkt);
    }

    fn ingest_packet_inner(&mut self, pkt: Packet) {
        self.packet_counter += 1;
        self.total_bytes += pkt.length as u64;
        self.rate_this_sec += 1;
        self.flow_tracker.update(&pkt);
        let process = self.socket_scope.observe(&pkt);
        self.route_ledger.observe(&pkt, process.as_deref());
        self.wire_pulse.observe(&pkt);
        self.net_registry.observe(&pkt.src);
        self.net_registry.observe(&pkt.dst);

        // Graph ingestion — extract before pkt is moved
        {
            let src   = pkt.src.clone();
            let dst   = pkt.dst.clone();
            let proto = pkt.protocol.clone();
            let sport = pkt.src_port;
            let dport = pkt.dst_port;
            let ts    = pkt.timestamp;
            let bytes = pkt.length as u64;
            let no    = pkt.no;
            self.operator_graph.on_packet(&src, &dst, &proto, sport, dport, ts, bytes, no);
        }

        // Security analysis. Critical built-in signatures open an incident for
        // explicit operator review; lower severities remain in the Security tab.
        let ids_before = self.security.ids_alerts.len();
        self.security.update(&pkt);
        let critical_ids: Vec<(String, String)> = self.security.ids_alerts[ids_before..]
            .iter()
            .filter(|alert| matches!(alert.severity, crate::net::security::Severity::Critical))
            .map(|alert| (alert.signature.to_string(), alert.detail.clone()))
            .collect();

        // Host inventory
        self.hosts.update(&pkt);

        // Sync OS guess from security engine → host inventory
        if let Some(os) = self.security.os_guess_for(&pkt.src) {
            if self.hosts.get(&pkt.src).and_then(|h| h.os_guess.as_deref()).is_none() {
                self.hosts.set_os_guess(&pkt.src, os);
            }
        }

        // Stream reassembly
        self.streams.ingest(&pkt);

        // Timeline
        self.timeline.ingest(&pkt);

        // TLS intelligence
        self.tls_tracker.ingest(&pkt);
        self.quic_scope.ingest(&pkt);

        // VLAN intelligence
        self.vlan_intel.ingest(&pkt);

        // IOC matching
        self.ioc_engine.check_packet(&pkt);

        // Critical alert actions in user rules share the same review workflow.
        let rule_hits_before = self.rule_engine.hits.len();
        self.rule_engine.evaluate(&pkt);
        let critical_rule_hits: Vec<(String, String, String, bool)> = self.rule_engine.hits[rule_hits_before..]
            .iter()
            .filter(|hit| matches!(&hit.action, RuleAction::Alert { severity: EvidenceSeverity::Critical, .. }))
            .map(|hit| (hit.rule_id.clone(), hit.rule_name.clone(), hit.message.clone(), hit.auto_contain))
            .collect();

        for (signature, detail) in critical_ids {
            self.open_industry_incident(&pkt, &signature, &detail);
        }
        for (rule_id, rule_name, message, auto_contain) in critical_rule_hits {
            self.open_user_rule_incident(&pkt, &rule_id, &rule_name, &message, auto_contain);
        }
        self.incidents.retain_packet(&pkt);

        // Credential extraction
        let new_creds = crate::net::inspector::extract_credentials(&pkt);
        if !new_creds.is_empty() {
            self.credentials.extend(new_creds);
            if self.credentials.len() > 1000 { self.credentials.drain(0..100); }
        }

        if self.recording {
            if let Some(ref mut writer) = self.pcap_writer { let _ = writer.write_packet(&pkt); }
        }

        if self.display_filter.input != self.filter.input {
            self.display_filter.set(self.filter.input.clone());
        }

        if Self::packet_matches_filter(&self.display_filter, &self.filter.input, &pkt) {
            self.filtered.push(self.packets.len());
            if self.selected.is_none() { self.selected = Some(0); }
        }

        self.packets.push_back(pkt);
        if self.packets.len() > MAX_PACKETS {
            self.packets.pop_front();
            self.rebuild_filtered();
        }
    }

    fn open_industry_incident(&mut self, packet: &Packet, signature: &str, detail: &str) {
        let id = self.incidents.open_or_update(
            IncidentSource::IndustrySignature,
            signature,
            detail,
            EvidenceSeverity::Critical,
            packet,
            self.packets.iter().cloned(),
        );
        self.freeze_incident_evidence(id);
        self.evaluate_traffic_latch(id, false);
        self.alert_overlay_open = true;
        self.set_status(format!("Critical incident #{id}: {signature}"));
    }

    fn open_user_rule_incident(
        &mut self,
        packet: &Packet,
        rule_id: &str,
        rule_name: &str,
        message: &str,
        auto_contain: bool,
    ) {
        let id = self.incidents.open_or_update(
            IncidentSource::UserRule,
            rule_id,
            format!("{rule_name}: {message}"),
            EvidenceSeverity::Critical,
            packet,
            self.packets.iter().cloned(),
        );
        self.freeze_incident_evidence(id);
        self.evaluate_traffic_latch(id, auto_contain);
        self.alert_overlay_open = true;
        self.set_status(format!("Critical incident #{id}: {rule_name}"));
    }

    fn freeze_incident_evidence(&mut self, incident_id: u64) {
        let incident = self.incidents.incidents.iter()
            .find(|incident| incident.id == incident_id)
            .cloned();
        let Some(incident) = incident else { return; };
        if let Err(error) = self.evidence_vault.freeze(&incident) {
            self.set_status(format!("Incident #{incident_id} retained in memory; evidence export failed: {error}"));
        }
    }

    fn evaluate_traffic_latch(&mut self, incident_id: u64, auto_contain_rule: bool) {
        let incident = self.incidents.incidents.iter()
            .find(|incident| incident.id == incident_id).cloned();
        if let Some(incident) = incident {
            let automatic_allowed = auto_contain_rule || self.has_independent_critical_signals(&incident);
            if let Some(path) = self.latch_helper_path.as_ref() {
                let backend = CommandLatch::new(path);
                self.traffic_latch.on_incident_with_auto_gate(&incident, &backend, automatic_allowed);
            } else {
                self.traffic_latch.on_incident_with_auto_gate(&incident, &NftablesLatch, automatic_allowed);
            }
        }
    }

    fn has_independent_critical_signals(&self, incident: &crate::analysis::incident::Incident) -> bool {
        let mut detectors = std::collections::BTreeSet::new();
        for candidate in self.incidents.incidents.iter().filter(|candidate| {
            candidate.attacker == incident.attacker
                && candidate.target == incident.target
                && candidate.severity == EvidenceSeverity::Critical
                && candidate.status == crate::analysis::incident::IncidentStatus::PendingReview
        }) {
            detectors.insert((candidate.source, candidate.detector.clone()));
        }
        detectors.len() >= 2
    }

    pub fn approve_active_latch(&mut self) {
        let Some(incident_id) = self.incidents.active().map(|incident| incident.id) else {
            self.set_status("No active incident has a pending TrafficLatch action");
            return;
        };
        let result = if let Some(path) = self.latch_helper_path.as_ref() {
            let backend = CommandLatch::new(path);
            self.traffic_latch.approve(incident_id, &backend)
        } else {
            self.traffic_latch.approve(incident_id, &NftablesLatch)
        };
        match result {
            Ok(action) => {
                let detail = action.detail.clone();
                self.set_status(format!("TrafficLatch: {detail}"));
            }
            Err(error) => self.set_status(format!("TrafficLatch error: {error}")),
        }
    }

    /// Open the retained incident packet history and record that it was reviewed.
    pub fn open_active_incident_analysis(&mut self) -> bool {
        if !self.incidents.mark_active_reviewed() {
            return false;
        }
        self.active_tab = Tab::Analysis;
        self.analysis_section = INCIDENT_ANALYSIS_SECTION;
        self.alert_overlay_open = false;
        self.set_status("Incident reviewed. Press C in Incident History to acknowledge the alert.");
        true
    }

    /// Acknowledgement hides the active alert but preserves its history.
    pub fn acknowledge_active_incident(&mut self) -> Result<(), &'static str> {
        self.incidents.acknowledge_active()?;
        self.alert_overlay_open = self.incidents.active().is_some();
        self.set_status("Incident acknowledged; retained packet history remains available.");
        Ok(())
    }

    /// Inject a crafted packet into the live packet list.
    pub fn craft_inject(&mut self) {
        let next_no = self.packet_counter + 1;
        match self.craft.build_packet(next_no) {
            Ok(pkt) => {
                let label = format!("Injected #{} — {} {} → {}",
                    next_no, pkt.protocol, pkt.src, pkt.dst);
                self.craft.result = Some(Ok(label));
                self.inject_packet(pkt);
            }
            Err(e) => {
                self.craft.result = Some(Err(e));
            }
        }
    }

    pub fn tick(&mut self) {
        self.rate_tick += 1;

        // Flood mode — inject packets from the crafter
        let flood_n = self.craft.flood_tick();
        for i in 0..flood_n {
            let next_no = self.packet_counter + 1 + i as u64;
            if let Ok(pkt) = self.craft.build_packet(next_no) {
                self.craft.flood_sent += 1;
                self.inject_packet(pkt);
            }
        }

        // Advance traceroute simulation one hop at a time
        self.traceroute.tick();

        // Advance port scanner
        if self.scan.running { self.scan.tick(); }

        if self.rate_tick % 20 == 1 {
            let _ = self.socket_scope.refresh();
            if self.tls_tracker.key_shelf.path.is_some() {
                let _ = self.tls_tracker.reload_key_log();
            }
        }

        // Advance PCAP replay — inject replayed packets
        let replayed = self.replay.tick();
        for pkt in replayed { self.ingest_packet_inner(pkt); }

        if self.capturing {
            if rand::random::<u8>() % 3 == 0 {
                let entry = crate::sim::dynamic::generate_entry(self.rate_tick);
                self.dyn_log.push(entry);
                if self.dyn_log.len() > 500 { self.dyn_log.remove(0); }
            }
        }

        if self.rate_tick % 10 == 0 {
            self.rate_history.push(self.rate_this_sec);
            self.rate_history.remove(0);
            self.rate_this_sec = 0;
        }

        // Expire transient status message
        if self.status_msg_ticks > 0 {
            self.status_msg_ticks -= 1;
            if self.status_msg_ticks == 0 { self.status_msg = None; }
        }

        self.yara_scan_new_objects();
        self.graph_tick();
        self.refresh_telemetry();
    }

    fn refresh_telemetry(&self) {
        self.telemetry.publish(TelemetrySnapshot {
            packets_total: self.packet_counter,
            bytes_total: self.total_bytes,
            visible_packets: self.filtered.len(),
            flows: self.flow_tracker.flows.len(),
            hosts: self.hosts.len(),
            security_findings: self.security.alert_count(),
            rule_hits: self.rule_engine.hits.len(),
            ioc_hits: self.ioc_engine.hit_count(),
            pending_incidents: self.incidents.incidents.iter()
                .filter(|incident| incident.status == crate::analysis::incident::IncidentStatus::PendingReview)
                .count(),
            evidence_exports: self.evidence_vault.exports.len(),
            packets_per_second: self.current_rate(),
            capturing: self.capturing,
            latency_p95_ms: self.wire_pulse.p95_ms().unwrap_or(0.0),
            enriched_addresses: self.net_registry.observed.len(),
        });
    }

    /// Incrementally sync all analysis subsystems into the operator graph,
    /// then recompute scores / paths / clusters on a throttled schedule.
    fn graph_tick(&mut self) {
        self.graph_tick_counter = self.graph_tick_counter.wrapping_add(1);

        // ── Sync IDS alerts ──────────────────────────────────────────────────
        let new_alerts = self.security.ids_alerts.len();
        if new_alerts > self.graph_ui.synced_alerts {
            for alert in &self.security.ids_alerts[self.graph_ui.synced_alerts..new_alerts] {
                self.operator_graph.on_ids_alert(
                    alert.signature,
                    &alert.severity.to_string(),
                    "",   // IdsAlert doesn't carry src/dst IP here — use empty
                    "",
                    alert.pkt_no,
                    0.0,  // no timestamp on IdsAlert
                );
            }
            self.graph_ui.synced_alerts = new_alerts;
        }

        // ── Sync IOC hits ────────────────────────────────────────────────────
        let new_ioc = self.ioc_engine.hits.len();
        if new_ioc > self.graph_ui.synced_ioc_hits {
            for hit in &self.ioc_engine.hits[self.graph_ui.synced_ioc_hits..new_ioc] {
                self.operator_graph.on_ioc_hit(
                    &hit.ioc.value,
                    &hit.ioc.kind.to_string(),
                    &hit.context,
                    hit.pkt_no,
                    hit.ts,
                    "",
                );
            }
            self.graph_ui.synced_ioc_hits = new_ioc;
        }

        // ── Sync credentials ─────────────────────────────────────────────────
        let new_creds = self.credentials.len();
        if new_creds > self.graph_ui.synced_creds {
            for cred in &self.credentials[self.graph_ui.synced_creds..new_creds] {
                // CredentialHit: proto, kind, value, pkt_no — no IP fields
                self.operator_graph.on_credential(
                    Some(cred.kind),
                    &cred.proto,
                    true,
                    "",
                    "",
                    0.0,
                    cred.pkt_no,
                );
            }
            self.graph_ui.synced_creds = new_creds;
        }

        // ── Sync rule hits ───────────────────────────────────────────────────
        let new_rules = self.rule_engine.hits.len();
        if new_rules > self.graph_ui.synced_rule_hits {
            for hit in &self.rule_engine.hits[self.graph_ui.synced_rule_hits..new_rules] {
                self.operator_graph.on_rule_hit(
                    &hit.rule_id,
                    &hit.rule_name,
                    &hit.message,
                    hit.pkt_no,
                    hit.ts,
                );
            }
            self.graph_ui.synced_rule_hits = new_rules;
        }

        // ── Sync carved objects ──────────────────────────────────────────────
        let new_objects = self.carved_objects.len();
        if new_objects > self.graph_ui.synced_objects {
            for obj in &self.carved_objects[self.graph_ui.synced_objects..new_objects] {
                self.operator_graph.on_carved_object(
                    obj.id,
                    &obj.kind,
                    &obj.sha256,
                    &obj.source,
                    obj.data.len(),
                    0.0,
                );
            }
            self.graph_ui.synced_objects = new_objects;
        }

        // ── Periodic recomputation (every 30 ticks ≈ 3s at 10Hz) ─────────────
        if self.graph_tick_counter % 30 == 0 {
            self.operator_graph.recompute_scores();
        }
        if self.graph_tick_counter % 60 == 0 {
            self.operator_graph.recompute_paths();
            self.operator_graph.recompute_clusters();
        }
    }

    pub fn toggle_capture(&mut self) { self.capturing = !self.capturing; }

    pub fn clear_packets(&mut self) {
        self.capturing = false;
        self.packets.clear();
        self.filtered.clear();
        self.selected = None;
        self.worklist = PacketWorklist::default();
        self.investigation_scroll = 0;
        self.reset_header_focus();
        self.total_bytes = 0;
        self.packet_counter = 0;
        self.flow_tracker.clear();
        self.flows_selected = None;
        self.stream_overlay = None;
        self.security.clear();
        self.credentials.clear();
        self.hosts.clear();
        self.streams.clear();
        self.timeline.clear();
        self.tls_tracker.clear();
        self.quic_scope.clear();
        self.vlan_intel.clear();
        self.ioc_engine.clear_hits();
        self.rule_engine.clear_hits();
        self.incidents.clear();
        self.evidence_vault.clear_session();
        self.socket_scope.traffic.clear();
        self.route_ledger.clear_session();
        self.traffic_latch.clear_session();
        self.wire_pulse.clear();
        self.net_registry.clear_session();
        self.alert_overlay_open = false;
        self.carved_objects.clear();
        self.yara_engine.clear_results();
        self.yara_scan_cursor = 0;
        self.operator_graph.clear();
        self.graph_ui = GraphUiState::default();
        self.graph_tick_counter = 0;
    }

    pub fn toggle_recording(&mut self) {
        if self.recording {
            if let Some(ref mut w) = self.pcap_writer { let _ = w.flush(); }
            self.pcap_writer = None;
            self.recording = false;
        } else {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs();
            let filename = format!("packrat_{}.pcap", ts);
            // Try CWD first, then home directory as fallback.
            let candidates = [
                filename.clone(),
                dirs_next::home_dir()
                    .map(|h| h.join(&filename).to_string_lossy().into_owned())
                    .unwrap_or_else(|| format!("/tmp/{}", filename)),
            ];
            for path in &candidates {
                if let Ok(writer) = PcapWriter::new(std::path::Path::new(path)) {
                    self.pcap_path = path.clone();
                    self.pcap_writer = Some(writer);
                    self.recording = true;
                    break;
                }
            }
        }
    }

    pub fn rebuild_filtered(&mut self) {
        // Sync the AST-based display filter from the input text
        self.display_filter.set(self.filter.input.clone());

        self.filtered = self.packets.iter().enumerate()
            .filter(|(_, p)| Self::packet_matches_filter(&self.display_filter, &self.filter.input, p))
            .map(|(i, _)| i)
            .collect();
        if let Some(sel) = self.selected {
            if sel >= self.filtered.len() {
                self.selected = if self.filtered.is_empty() { None } else { Some(self.filtered.len() - 1) };
            }
        }
    }

    fn packet_matches_filter(
        display_filter: &DisplayFilter,
        input: &str,
        p: &Packet,
    ) -> bool {
        if display_filter.is_active() {
            // Use the advanced packet inspection AST evaluator.
            display_filter.matches(p, false, &[])
        } else if display_filter.has_error() {
            // Parse error: fall back to simple text match.
            crate::analysis::display_filter::DisplayFilter::matches_simple(input, p)
        } else {
            true
        }
    }

    pub fn selected_packet(&self) -> Option<&Packet> {
        self.selected.and_then(|i| self.filtered.get(i)).and_then(|&pi| self.packets.get(pi))
    }

    pub fn active_investigation_packet(&self) -> Option<&Packet> {
        self.worklist.active_packet_no()
            .and_then(|packet_no| self.packet_by_no(packet_no))
            .or_else(|| self.selected_packet())
    }

    pub fn active_investigation_stream(&self) -> Option<&ReassembledStream> {
        let packet = self.active_investigation_packet()?;
        let key = StreamKey::from_packet(packet)?;
        self.streams.get(&key.id())
    }

    pub fn open_active_investigation_stream_overlay(&mut self) {
        let Some(packet) = self.active_investigation_packet() else {
            self.set_status("No packet selected for stream follow");
            return;
        };
        let Some(key) = StreamKey::from_packet(packet) else {
            self.set_status("Active packet is not TCP-backed");
            return;
        };
        let Some(stream) = self.streams.get(&key.id()) else {
            self.set_status("No reassembled stream is available for this packet yet");
            return;
        };

        let mut segments = Vec::new();
        for segment in &stream.segments {
            let data = if segment.from_client {
                &stream.client_data
            } else {
                &stream.server_data
            };
            let end = segment.offset.saturating_add(segment.length).min(data.len());
            if segment.offset < end {
                segments.push((segment.from_client, data[segment.offset..end].to_vec()));
            }
        }
        if segments.is_empty() {
            self.set_status("Reassembled stream has no payload bytes yet");
            return;
        }
        self.stream_overlay = Some((key.id(), segments));
    }

    pub fn mark_selected_packet_for_investigation(&mut self) {
        let Some(packet_no) = self.selected_packet().map(|packet| packet.no) else {
            self.set_status("No packet selected to add to worklist");
            return;
        };
        let added = self.worklist.add(packet_no);
        self.set_status(if added {
            format!("Added packet #{packet_no} to worklist")
        } else {
            format!("Packet #{packet_no} is already in worklist")
        });
    }

    pub fn open_selected_packet_investigation(&mut self) {
        let Some(packet_no) = self.selected_packet().map(|packet| packet.no) else {
            self.set_status("No packet selected to investigate");
            return;
        };
        self.worklist.add(packet_no);
        self.active_tab = Tab::Investigate;
        self.investigation_scroll = 0;
        self.reset_header_focus();
    }

    pub fn toggle_worklist(&mut self) {
        self.worklist.open = !self.worklist.open;
    }

    pub fn close_worklist(&mut self) {
        self.worklist.open = false;
    }

    pub fn worklist_next_packet(&mut self) {
        self.worklist.next();
        self.investigation_scroll = 0;
        self.reset_header_focus();
    }

    pub fn worklist_prev_packet(&mut self) {
        self.worklist.prev();
        self.investigation_scroll = 0;
        self.reset_header_focus();
    }

    pub fn remove_active_worklist_packet(&mut self) {
        match self.worklist.remove_active() {
            Some(packet_no) => self.set_status(format!("Removed packet #{packet_no} from worklist")),
            None => self.set_status("Worklist is empty"),
        }
        self.reset_header_focus();
    }

    pub fn investigation_next_view(&mut self) {
        let next = (self.investigation_view.index() + 1) % InvestigationView::COUNT;
        self.investigation_view = InvestigationView::from_index(next);
        self.investigation_scroll = 0;
        self.reset_header_focus();
    }

    pub fn investigation_prev_view(&mut self) {
        let current = self.investigation_view.index();
        let prev = if current == 0 { InvestigationView::COUNT - 1 } else { current - 1 };
        self.investigation_view = InvestigationView::from_index(prev);
        self.investigation_scroll = 0;
        self.reset_header_focus();
    }

    pub fn investigation_scroll_down(&mut self) {
        self.investigation_scroll = self.investigation_scroll.saturating_add(1);
    }

    pub fn investigation_scroll_up(&mut self) {
        self.investigation_scroll = self.investigation_scroll.saturating_sub(1);
    }

    pub fn packet_header_fields(&self) -> Vec<PacketField> {
        self.active_investigation_packet()
            .map(packet_fields::extract_fields)
            .unwrap_or_default()
    }

    pub fn visible_packet_header_fields(&self) -> Vec<PacketField> {
        packet_fields::filter_fields(&self.packet_header_fields(), &self.header_search)
    }

    pub fn header_cursor_down(&mut self) {
        let count = self.visible_packet_header_fields().len();
        if count == 0 {
            self.header_cursor = 0;
        } else {
            self.header_cursor = (self.header_cursor + 1).min(count - 1);
        }
    }

    pub fn header_cursor_up(&mut self) {
        self.header_cursor = self.header_cursor.saturating_sub(1);
    }

    pub fn header_cursor_home(&mut self) {
        self.header_cursor = 0;
    }

    pub fn header_cursor_end(&mut self) {
        self.header_cursor = self.visible_packet_header_fields().len().saturating_sub(1);
    }

    pub fn start_header_search(&mut self) {
        self.header_searching = true;
        self.header_cursor = 0;
    }

    pub fn close_header_search(&mut self) {
        self.header_searching = false;
    }

    pub fn update_header_search(&mut self, c: char) {
        self.header_search.push(c);
        self.header_cursor = 0;
    }

    pub fn pop_header_search(&mut self) {
        self.header_search.pop();
        self.header_cursor = 0;
    }

    pub fn clear_header_search(&mut self) {
        self.header_search.clear();
        self.header_cursor = 0;
    }

    pub fn apply_selected_header_filter(&mut self) {
        let fields = self.visible_packet_header_fields();
        let Some(field) = fields.get(self.header_cursor).or_else(|| fields.first()) else {
            self.set_status("No packet header field selected");
            return;
        };
        let Some(expr) = packet_fields::filter_expression(field) else {
            self.set_status(format!("No display filter mapping for {}", field.path));
            return;
        };
        self.filter.input = expr.clone();
        self.filter.active = false;
        self.rebuild_filtered();
        self.active_tab = Tab::Packets;
        self.set_status(format!("Filter applied: {expr}"));
    }

    fn reset_header_focus(&mut self) {
        self.header_cursor = 0;
        self.header_searching = false;
    }

    pub fn open_settings(&mut self) {
        self.settings_open = true;
        self.settings_cursor = 0;
    }

    pub fn close_settings(&mut self) {
        self.settings_open = false;
    }

    pub fn activate_settings_selection(&mut self) {
        match self.settings_cursor {
            1 => {
                self.toggle_capture();
                self.set_status(if self.capturing { "Capture started" } else { "Capture stopped" });
            }
            3 => {
                self.traffic_latch.mode = match self.traffic_latch.mode {
                    LatchMode::Monitor => LatchMode::Preview,
                    LatchMode::Preview => LatchMode::Manual,
                    LatchMode::Manual => LatchMode::Automatic,
                    LatchMode::Automatic => LatchMode::Monitor,
                };
                self.set_status(format!("TrafficLatch mode set to {}", self.traffic_latch.mode));
            }
            _ => {}
        }
    }

    pub fn current_rate(&self) -> u32 { *self.rate_history.last().unwrap_or(&0) }

    pub fn move_down(&mut self) {
        match self.active_tab {
            Tab::Packets  => {
                if let Some(sel) = self.selected {
                    if sel + 1 < self.filtered.len() { self.selected = Some(sel + 1); }
                } else if !self.filtered.is_empty() { self.selected = Some(0); }
            }
            Tab::Investigate => self.investigation_scroll_down(),
            Tab::Analysis => { if self.analysis_section < INCIDENT_ANALYSIS_SECTION { self.analysis_section += 1; } }
            // j = toward tail (decrease offset-from-end)
            Tab::Dynamic  => { self.dyn_scroll = self.dyn_scroll.saturating_sub(1); }
            Tab::Flows => {
                let len = self.flow_tracker.flows.len();
                if let Some(sel) = self.flows_selected {
                    if sel + 1 < len { self.flows_selected = Some(sel + 1); }
                } else if len > 0 {
                    self.flows_selected = Some(0);
                }
            }
            _ => {}
        }
    }

    pub fn move_up(&mut self) {
        match self.active_tab {
            Tab::Packets  => { if let Some(sel) = self.selected { if sel > 0 { self.selected = Some(sel - 1); } } }
            Tab::Investigate => self.investigation_scroll_up(),
            Tab::Analysis => { if self.analysis_section > 0 { self.analysis_section -= 1; } }
            // k = away from tail (increase offset-from-end), clamped to log length
            Tab::Dynamic  => {
                let max = self.dyn_log.len().saturating_sub(1);
                if self.dyn_scroll < max { self.dyn_scroll += 1; }
            }
            Tab::Flows => {
                if let Some(sel) = self.flows_selected {
                    if sel > 0 { self.flows_selected = Some(sel - 1); }
                }
            }
            _ => {}
        }
    }

    pub fn flows_sort_bytes(&mut self)   { self.flows_sort = FlowSort::Bytes; }
    pub fn flows_sort_packets(&mut self) { self.flows_sort = FlowSort::Packets; }
    pub fn flows_sort_time(&mut self)    { self.flows_sort = FlowSort::Time; }
    pub fn flows_sort_beacon(&mut self)  { self.flows_sort = FlowSort::BeaconScore; }

    pub fn flows_open_stream(&mut self) {
        let sorted = self.flow_tracker.sorted_flows(&self.flows_sort);
        if let Some(sel) = self.flows_selected {
            if let Some(flow) = sorted.get(sel) {
                let key = flow.key.clone();
                let initiator = flow.initiator.clone();
                let mut segments: Vec<(bool, Vec<u8>)> = Vec::new();
                for pkt in &self.packets {
                    let pkt_key = FlowKey::from_packet(pkt);
                    if pkt_key == key {
                        let is_init = pkt.src == initiator;
                        let offset = crate::analysis::stream::tcp_payload_offset(pkt);
                        let payload = if pkt.bytes.len() > offset { pkt.bytes[offset..].to_vec() } else { Vec::new() };
                        if !payload.is_empty() {
                            segments.push((is_init, payload));
                        }
                    }
                }
                let title = format!("{}:{} <-> {}:{} ({})",
                    key.ep1.0, key.ep1.1, key.ep2.0, key.ep2.1, key.proto);
                self.stream_overlay = Some((title, segments));
            }
        }
    }

    pub fn flows_jump_to_packets(&mut self) {
        let sorted = self.flow_tracker.sorted_flows(&self.flows_sort);
        if let Some(sel) = self.flows_selected {
            if let Some(flow) = sorted.get(sel) {
                let ip = flow.key.ep1.0.clone();
                self.filter.input = ip;
                self.filter.active = false;
                self.rebuild_filtered();
                self.active_tab = crate::tabs::Tab::Packets;
            }
        }
    }

    pub fn move_top(&mut self) {
        if matches!(self.active_tab, Tab::Packets) {
            self.selected = if self.filtered.is_empty() { None } else { Some(0) };
        } else if matches!(self.active_tab, Tab::Investigate) {
            self.investigation_scroll = 0;
        }
    }

    pub fn move_bottom(&mut self) {
        match self.active_tab {
            Tab::Packets if !self.filtered.is_empty() => {
                self.selected = Some(self.filtered.len() - 1);
            }
            Tab::Dynamic => {
                self.dyn_scroll = 0; // 0 = tail (offset-from-end model)
            }
            Tab::Investigate => {
                self.investigation_scroll = usize::MAX / 2;
            }
            _ => {}
        }
    }

    pub fn page_down(&mut self) {
        if matches!(self.active_tab, Tab::Packets) {
            if let Some(sel) = self.selected {
                self.selected = Some((sel + 10).min(self.filtered.len().saturating_sub(1)));
            }
        }
    }

    pub fn page_up(&mut self) {
        if matches!(self.active_tab, Tab::Packets) {
            if let Some(sel) = self.selected { self.selected = Some(sel.saturating_sub(10)); }
        }
    }

    pub fn next_tab(&mut self) {
        let views = self.active_tab.workspace().views();
        let current = views.iter().position(|view| *view == self.active_tab).unwrap_or(0);
        self.active_tab = views[(current + 1) % views.len()];
    }

    pub fn prev_tab(&mut self) {
        let views = self.active_tab.workspace().views();
        let current = views.iter().position(|view| *view == self.active_tab).unwrap_or(0);
        self.active_tab = views[if current == 0 { views.len() - 1 } else { current - 1 }];
    }

    pub fn select_workspace(&mut self, workspace: Workspace) {
        self.active_tab = workspace.home();
        self.view_menu_open = false;
        self.view_menu_cursor = 0;
    }

    pub fn open_view_menu(&mut self) {
        let views = self.active_tab.workspace().views();
        self.view_menu_cursor = views.iter().position(|view| *view == self.active_tab).unwrap_or(0);
        self.view_menu_open = true;
    }

    pub fn view_menu_next(&mut self) {
        let max = self.active_tab.workspace().views().len().saturating_sub(1);
        self.view_menu_cursor = (self.view_menu_cursor + 1).min(max);
    }

    pub fn view_menu_prev(&mut self) {
        self.view_menu_cursor = self.view_menu_cursor.saturating_sub(1);
    }

    pub fn activate_view_menu_selection(&mut self) {
        if let Some(view) = self.active_tab.workspace().views().get(self.view_menu_cursor) {
            self.active_tab = *view;
        }
        self.view_menu_open = false;
    }

    /// Return from a detail view to the workspace's primary view.
    pub fn return_to_workspace_home(&mut self) -> bool {
        if self.active_tab.is_workspace_home() {
            return false;
        }
        self.active_tab = self.active_tab.workspace().home();
        true
    }

    pub fn security_subtab_next(&mut self) {
        self.security_tab = match self.security_tab {
            SecuritySubTab::Ids           => SecuritySubTab::Credentials,
            SecuritySubTab::Credentials   => SecuritySubTab::OsFingerprint,
            SecuritySubTab::OsFingerprint => SecuritySubTab::ArpWatch,
            SecuritySubTab::ArpWatch      => SecuritySubTab::DnsTunnel,
            SecuritySubTab::DnsTunnel     => SecuritySubTab::HttpAnalytics,
            SecuritySubTab::HttpAnalytics => SecuritySubTab::TlsWeakness,
            SecuritySubTab::TlsWeakness   => SecuritySubTab::BruteForce,
            SecuritySubTab::BruteForce    => SecuritySubTab::VulnHits,
            SecuritySubTab::VulnHits      => SecuritySubTab::IocHits,
            SecuritySubTab::IocHits       => SecuritySubTab::VlanIntel,
            SecuritySubTab::VlanIntel     => SecuritySubTab::ProcessScope,
            SecuritySubTab::ProcessScope  => SecuritySubTab::RoutePolicy,
            SecuritySubTab::RoutePolicy   => SecuritySubTab::WirePulse,
            SecuritySubTab::WirePulse     => SecuritySubTab::NetRegistry,
            SecuritySubTab::NetRegistry   => SecuritySubTab::Replay,
            SecuritySubTab::Replay        => SecuritySubTab::Ids,
        };
    }

    pub fn security_subtab_prev(&mut self) {
        self.security_tab = match self.security_tab {
            SecuritySubTab::Ids           => SecuritySubTab::Replay,
            SecuritySubTab::Credentials   => SecuritySubTab::Ids,
            SecuritySubTab::OsFingerprint => SecuritySubTab::Credentials,
            SecuritySubTab::ArpWatch      => SecuritySubTab::OsFingerprint,
            SecuritySubTab::DnsTunnel     => SecuritySubTab::ArpWatch,
            SecuritySubTab::HttpAnalytics => SecuritySubTab::DnsTunnel,
            SecuritySubTab::TlsWeakness   => SecuritySubTab::HttpAnalytics,
            SecuritySubTab::BruteForce    => SecuritySubTab::TlsWeakness,
            SecuritySubTab::VulnHits      => SecuritySubTab::BruteForce,
            SecuritySubTab::IocHits       => SecuritySubTab::VulnHits,
            SecuritySubTab::VlanIntel     => SecuritySubTab::IocHits,
            SecuritySubTab::ProcessScope  => SecuritySubTab::VlanIntel,
            SecuritySubTab::RoutePolicy   => SecuritySubTab::ProcessScope,
            SecuritySubTab::WirePulse     => SecuritySubTab::RoutePolicy,
            SecuritySubTab::NetRegistry   => SecuritySubTab::WirePulse,
            SecuritySubTab::Replay        => SecuritySubTab::NetRegistry,
        };
    }

    pub fn cycle_route_policy_mode(&mut self) {
        match self.route_ledger.cycle_mode() {
            Ok(mode) => self.set_status(format!("Route policy mode: {mode}")),
            Err(error) => self.set_status(format!("Route policy error: {error}")),
        }
    }

    pub fn promote_observed_routes(&mut self) {
        match self.route_ledger.promote_observed() {
            Ok(count) => self.set_status(format!("Added {count} routes to the baseline")),
            Err(error) => self.set_status(format!("Route policy error: {error}")),
        }
    }

    pub fn load_key_log(&mut self, path: impl AsRef<std::path::Path>) {
        match self.tls_tracker.load_key_log(path.as_ref()) {
            Ok(count) => self.set_status(format!("Loaded {count} TLS/QUIC key-log secrets")),
            Err(error) => self.set_status(format!("Key-log error: {error}")),
        }
    }

    pub fn refresh_selected_whois(&mut self) {
        let address = self.net_registry.sorted().get(self.security_scroll).map(|entry| entry.address);
        let Some(address) = address else {
            self.set_status("No address selected for refresh");
            return;
        };
        if let Some(path) = self.reputation_helper_path.clone() {
            match self.net_registry.refresh_reputation_with_helper(address, path) {
                Ok(identity) => {
                    let detail = identity.reputation.as_ref()
                        .map(|finding| format!("{} ({})", finding.label, finding.severity))
                        .unwrap_or_else(|| "no finding".into());
                    self.set_status(format!("Reputation {address}: {detail}"));
                }
                Err(error) => self.set_status(format!("Reputation error: {error}")),
            }
            return;
        }
        match self.net_registry.refresh_whois(address) {
            Ok(identity) => {
                let organization = identity.organization.clone();
                self.set_status(format!("WHOIS {address}: {organization}"));
            }
            Err(error) => self.set_status(format!("WHOIS error: {error}")),
        }
    }

    pub fn refresh_selected_encrypted_reputation(&mut self) {
        let Some(path) = self.reputation_helper_path.clone() else {
            self.set_status("Configure --reputation-helper to refresh JA4 or RatQ reputation");
            return;
        };
        let fingerprint = match self.encrypted_view {
            EncryptedView::Tls => self.tls_tracker.all()
                .get(self.tls_selected)
                .and_then(|session| session.ja4.clone()),
            EncryptedView::Quic => self.quic_scope.all()
                .get(self.tls_selected)
                .map(|connection| connection.ratq.clone()),
        };
        let Some(fingerprint) = fingerprint.filter(|value| !value.is_empty()) else {
            self.set_status("No selected encrypted fingerprint to refresh");
            return;
        };
        match self.net_registry.refresh_fingerprint_reputation_with_helper(&fingerprint, path) {
            Ok(finding) => self.set_status(format!(
                "Reputation {fingerprint}: {} ({})",
                finding.label, finding.severity,
            )),
            Err(error) => self.set_status(format!("Reputation error: {error}")),
        }
    }
}

/// Convert a byte slice to a printable ASCII line (non-printable → '.').
fn printable_line(data: &[u8]) -> String {
    data.iter().map(|&b| {
        if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }
    }).collect()
}
