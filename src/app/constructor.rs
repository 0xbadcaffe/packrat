use super::*;

impl App {
    pub fn new(packet_tx: Sender<Packet>) -> Self {
        Self::new_with_mode(packet_tx, StartupMode::Capture)
    }

    pub fn new_with_mode(packet_tx: Sender<Packet>, startup_mode: StartupMode) -> Self {
        let preferences = theme_store::load();
        let iface_list = list_interfaces(startup_mode == StartupMode::Simulation);
        let selected_iface = iface_list.first().cloned().unwrap_or_default();
        let mut alert_center = AlertCenter::default();
        alert_center.automation_mode = match preferences.alert_automation {
            1 => AutomationMode::Watch,
            2 => AutomationMode::Triage,
            _ => AutomationMode::Off,
        };
        let mut app = Self {
            active_tab: Workspace::from_index(preferences.startup_workspace).home(),
            navigation_history: Vec::new(),
            packets: VecDeque::new(),
            packet_index_base: 0,
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
            restoring_project: false,
            pcap_path: String::new(),
            pcap_writer: None,
            show_help: false,
            help_scroll: 0,
            dissectors: crate::dissector::load(),
            strings_search_active: false,
            strings_selected: None,
            strings_scroll: 0,
            flow_tracker: FlowTracker::new(),
            flows_selected: None,
            flows_sort: FlowSort::Bytes,
            stream_overlay: None,
            packet_comparison: None,
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
            security_tab: SecuritySubTab::Alerts,
            alert_center,
            security_scroll: 0,
            scanner_scroll: 0,
            replay_editing: false,
            pcap_import_editing: false,
            pcap_import_path: String::new(),
            scan_editing: false,
            hosts: HostInventory::default(),
            tag_store: TagStore::default(),
            notebook: Notebook::default(),
            streams: StreamAssembler::default(),
            timeline: ProtocolTimelines::default(),
            tls_tracker: TlsTracker::default(),
            quic_scope: QuicScope::default(),
            vlan_intel: VlanIntel::default(),
            ioc_engine: {
                let mut e = IocEngine::default();
                e.load_from_dir();
                e
            },
            rule_engine: {
                let mut e = RuleEngine::default();
                e.load_from_dir();
                e
            },
            incidents: IncidentStore::default(),
            endpoint_evidence: Vec::new(),
            packet_archive: None,
            evidence_vault: EvidenceVault::default(),
            telemetry: TelemetryHub::default(),
            socket_scope: SocketScope::default(),
            route_ledger: RouteLedger::default(),
            traffic_latch: TrafficLatch::default(),
            live_response_eligible: true,
            processing_live_packet: false,
            live_response_incidents: std::collections::HashSet::new(),
            response_preview: Vec::new(),
            latch_helper_path: None,
            wire_pulse: WirePulse::default(),
            net_registry: NetRegistry::default(),
            reputation_helper_path: None,
            capture_helper_path: None,
            alert_overlay_open: false,
            carver: Carver::default(),
            carved_objects: Vec::new(),
            workbench: ProtocolWorkbench::default(),
            diff_engine: DiffEngine::default(),
            diff_scroll: 0,
            diff_baseline: Vec::new(),
            job_queue: JobQueue::default(),
            display_filter: DisplayFilter::default(),
            notebook_scroll: 0,
            notebook_input: String::new(),
            notebook_editing: false,
            notebook_searching: false,
            notebook_search: String::new(),
            hosts_scroll: 0,
            hosts_search: String::new(),
            hosts_searching: false,
            hosts_tagging: false,
            hosts_tag_input: String::new(),
            tls_scroll: 0,
            tls_selected: 0,
            encrypted_view: EncryptedView::Tls,
            objects_scroll: 0,
            objects_subtab: ObjectsSubTab::Objects,
            yara_rules_scroll: 0,
            yara_matches_scroll: 0,
            yara_engine: YaraEngine::new(),
            yara_scan_cursor: 0,
            rules_scroll: 0,
            operator_graph: OperatorGraphEngine::default(),
            graph_ui: GraphUiState::default(),
            graph_tick_counter: 0,
            search_open: false,
            search_query: String::new(),
            search_results: Vec::new(),
            search_selected: 0,
            autopsy_state: None,
            selected_theme_name: preferences.theme,
            theme_picker_open: false,
            theme_picker_cursor: 0,
            view_menu_open: false,
            view_menu_cursor: 0,
            worklist: InvestigationTray::default(),
            investigation_view: InvestigationView::Summary,
            investigation_scroll: 0,
            header_cursor: 0,
            byte_cursor: 0,
            header_searching: false,
            header_search: String::new(),
            settings_open: false,
            settings_cursor: 0,
            auto_scroll: preferences.auto_scroll,
            preferred_workspace: Workspace::from_index(preferences.startup_workspace),
            persist_preferences: true,
            current_project_name: None,
            current_project_path: None,
            project_dirty: false,
            project_manager_open: false,
            project_manager: ProjectManagerState::default(),
            status_msg: None,
            status_msg_ticks: 0,
        };

        if startup_mode == StartupMode::Simulation {
            app.confirm_iface();
        }

        app
    }
}
