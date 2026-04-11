use std::collections::VecDeque;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;

use crate::analysis::carving::{Carver, CarvedObject};
use crate::analysis::yara::YaraEngine;
use crate::ui::autopsy_overlay::AutopsyState;
use crate::analysis::diff::DiffEngine;
use crate::analysis::display_filter::DisplayFilter;
use crate::analysis::ioc::IocEngine;
use crate::analysis::jobs::JobQueue;
use crate::analysis::notebook::Notebook;
use crate::analysis::operator_graph::{GraphUiState, OperatorGraphEngine};
use crate::analysis::protocol_workbench::ProtocolWorkbench;
use crate::analysis::rules::RuleEngine;
use crate::analysis::stream::StreamAssembler;
use crate::analysis::timeline::ProtocolTimelines;
use crate::analysis::tls::TlsTracker;
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
use crate::tabs::Tab;
use crate::traceroute::TracerouteState;

const MAX_PACKETS: usize = 10_000;

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

fn list_interfaces() -> Vec<String> {
    let mut ifaces = vec!["simulated".to_string()];
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
    pub replay_editing: bool,
    pub scan_editing: bool,
    // ─── Phase 1–4 analysis state ──────────────────────────────────────────────
    pub hosts:           HostInventory,
    pub tag_store:       TagStore,
    pub notebook:        Notebook,
    pub streams:         StreamAssembler,
    pub timeline:        ProtocolTimelines,
    pub tls_tracker:     TlsTracker,
    pub ioc_engine:      IocEngine,
    pub rule_engine:     RuleEngine,
    pub carver:          Carver,
    pub carved_objects:  Vec<CarvedObject>,
    pub workbench:       ProtocolWorkbench,
    pub diff_engine:     DiffEngine,
    pub job_queue:       JobQueue,
    pub display_filter:  DisplayFilter,
    // Notebook UI state
    pub notebook_scroll: usize,
    pub notebook_input:  String,
    pub notebook_editing: bool,
    // Hosts UI state
    pub hosts_scroll:    usize,
    pub hosts_search:    String,
    pub hosts_searching: bool,
    // TLS UI state
    pub tls_scroll:      usize,
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
    // ─── Status / feedback message (transient, cleared after a few ticks) ─────
    pub status_msg:      Option<String>,
    status_msg_ticks:    u8,
}

impl App {
    pub fn new(packet_tx: Sender<Packet>) -> Self {
        let iface_list = list_interfaces();
        Self {
            active_tab: Tab::Packets,
            packets: VecDeque::new(),
            filtered: Vec::new(),
            selected: None,
            total_bytes: 0,
            packet_counter: 0,
            capturing: false,
            capture_handle: None,
            packet_tx,
            picking_iface: true,
            iface_list,
            iface_sel: 0,
            selected_iface: "simulated".to_string(),
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
            replay_editing: false,
            scan_editing: false,
            hosts:            HostInventory::default(),
            tag_store:        TagStore::default(),
            notebook:         Notebook::default(),
            streams:          StreamAssembler::default(),
            timeline:         ProtocolTimelines::default(),
            tls_tracker:      TlsTracker::default(),
            ioc_engine:       IocEngine::default(),
            rule_engine:      RuleEngine::default(),
            carver:           Carver::default(),
            carved_objects:   Vec::new(),
            workbench:        ProtocolWorkbench::default(),
            diff_engine:      DiffEngine::default(),
            job_queue:        JobQueue::default(),
            display_filter:   DisplayFilter::default(),
            notebook_scroll:  0,
            notebook_input:   String::new(),
            notebook_editing: false,
            hosts_scroll:     0,
            hosts_search:     String::new(),
            hosts_searching:  false,
            tls_scroll:            0,
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
            status_msg:       None,
            status_msg_ticks: 0,
        }
    }

    /// Set a transient status message shown in the status bar for ~3 seconds.
    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_msg = Some(msg.into());
        self.status_msg_ticks = 30; // 30 ticks ≈ 3s at 10Hz
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
        let mut sections = crate::net::tree::build_tree(pkt);
        crate::dissector::apply(&self.dissectors, pkt, &mut sections);
        self.lua_plugins.apply(pkt, &mut sections);
        sections
    }

    pub fn iface_down(&mut self) {
        if self.iface_sel + 1 < self.iface_list.len() { self.iface_sel += 1; }
    }

    pub fn iface_up(&mut self) { self.iface_sel = self.iface_sel.saturating_sub(1); }

    pub fn confirm_iface(&mut self) {
        self.selected_iface = self.iface_list[self.iface_sel].clone();
        self.picking_iface = false;
        self.abort_capture();

        if self.selected_iface == "simulated" {
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

        // Security analysis
        self.security.update(&pkt);

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

        // IOC matching
        self.ioc_engine.check_packet(&pkt);

        // Rule engine
        self.rule_engine.evaluate(&pkt);

        // Credential extraction
        let new_creds = crate::net::inspector::extract_credentials(&pkt);
        if !new_creds.is_empty() {
            self.credentials.extend(new_creds);
            if self.credentials.len() > 1000 { self.credentials.drain(0..100); }
        }

        if self.recording {
            if let Some(ref mut writer) = self.pcap_writer { let _ = writer.write_packet(&pkt); }
        }

        if self.filter.matches(&pkt) {
            self.filtered.push(self.packets.len());
            if self.selected.is_none() { self.selected = Some(0); }
        }

        self.packets.push_back(pkt);
        if self.packets.len() > MAX_PACKETS {
            self.packets.pop_front();
            self.rebuild_filtered();
        }
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
        self.ioc_engine.clear_hits();
        self.rule_engine.clear_hits();
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
        self.filtered = self.packets.iter().enumerate()
            .filter(|(_, p)| self.filter.matches(p))
            .map(|(i, _)| i)
            .collect();
        if let Some(sel) = self.selected {
            if sel >= self.filtered.len() {
                self.selected = if self.filtered.is_empty() { None } else { Some(self.filtered.len() - 1) };
            }
        }
    }

    pub fn selected_packet(&self) -> Option<&Packet> {
        self.selected.and_then(|i| self.filtered.get(i)).and_then(|&pi| self.packets.get(pi))
    }

    pub fn current_rate(&self) -> u32 { *self.rate_history.last().unwrap_or(&0) }

    pub fn move_down(&mut self) {
        match self.active_tab {
            Tab::Packets  => {
                if let Some(sel) = self.selected {
                    if sel + 1 < self.filtered.len() { self.selected = Some(sel + 1); }
                } else if !self.filtered.is_empty() { self.selected = Some(0); }
            }
            Tab::Analysis => { if self.analysis_section < 10 { self.analysis_section += 1; } }
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
                        // Skip headers: try offset 54 (Eth14+IP20+TCP20)
                        let payload = if pkt.bytes.len() > 54 { pkt.bytes[54..].to_vec() } else { Vec::new() };
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
        let next = (self.active_tab.index() + 1) % Tab::COUNT;
        self.active_tab = Tab::from_index(next);
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
            SecuritySubTab::VulnHits      => SecuritySubTab::Replay,
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
            SecuritySubTab::Replay        => SecuritySubTab::VulnHits,
        };
    }
}

/// Convert a byte slice to a printable ASCII line (non-printable → '.').
fn printable_line(data: &[u8]) -> String {
    data.iter().map(|&b| {
        if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }
    }).collect()
}
