use super::*;

impl App {
    /// Reload JSON rules from ~/.config/packrat/rules/ and show status.
    pub fn reload_rules(&mut self) {
        let core_handle = self.core.clone();
        let mut core = core_handle.edit();
        core.rule_engine.rules.clear();
        let errs = core.rule_engine.load_from_dir();
        let count = core.rule_engine.rules.len();
        if errs.is_empty() {
            self.set_status(format!("Rules: {count} rules loaded"));
        } else {
            self.set_status(format!("Rules: {count} rules, {} error(s)", errs.len()));
        }
    }

    /// Load IOC feeds from ~/.config/packrat/ioc/ and show status.
    pub fn reload_ioc_feeds(&mut self) {
        let core_handle = self.core.clone();
        let mut core = core_handle.edit();
        let errs = core.ioc_engine.load_from_dir();
        let count = core.ioc_engine.ioc_count();
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
                self.set_status(format!(
                    "Loaded {} packets from {}",
                    count,
                    path_buf
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(path)
                ));
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
        self.diff_engine
            .compute(&self.diff_baseline.clone(), &current);
        self.active_tab = crate::tabs::Tab::Diff;
        self.diff_scroll = 0;
        self.set_status(format!(
            "Diff: {} baseline vs {} current packets",
            self.diff_baseline.len(),
            current.len()
        ));
    }

    /// Apply the current `hosts_tag_input` as a tag to the host at `hosts_scroll`.
    pub fn apply_host_tag(&mut self) {
        let core_handle = self.core.clone();
        let mut core = core_handle.edit();
        let tag = self.hosts_tag_input.trim().to_string();
        if tag.is_empty() {
            return;
        }
        let hosts = core.hosts.all();
        if let Some(h) = hosts.get(self.hosts_scroll) {
            let ip = h.ip.clone();
            if let Some(host) = core.hosts.get_mut(&ip) {
                host.tags.insert(tag.clone());
            }
            self.set_status(format!("Tagged {ip} as \"{tag}\""));
        }
    }

    /// Remove a tag from the host at `hosts_scroll` (removes the first tag, alphabetically).
    pub fn remove_host_tag(&mut self) {
        let core_handle = self.core.clone();
        let mut core = core_handle.edit();
        let hosts = core.hosts.all();
        if let Some(h) = hosts.get(self.hosts_scroll) {
            let ip = h.ip.clone();
            let tag = h.tags.iter().min().cloned();
            if let (Some(host), Some(t)) = (core.hosts.get_mut(&ip), tag) {
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
        let core_handle = self.core.clone();
        let mut core = core_handle.edit();

        // Seed IOC hits for the C2 IP
        for ip in scenario::ioc_ips() {
            core.ioc_engine.load_ioc(crate::analysis::ioc::Ioc {
                kind: crate::analysis::ioc::IocKind::Ip,
                value: ip.into(),
                description: "Operation Quiet Beacon C2 infrastructure".into(),
                source: "scenario".into(),
            });
        }
        // Re-scan packets against IOCs now that they're loaded
        let pkts: Vec<_> = self.packets.iter().cloned().collect();
        for pkt in &pkts {
            core.ioc_engine.check_packet(pkt);
        }

        // Seed notebook notes
        for (text, ev_str) in scenario::notebook_notes() {
            let ev = ev_str.map(|s| {
                crate::model::evidence::EvidenceRef::Packet(crate::model::evidence::PacketRef(
                    s.trim_start_matches("pkt#").parse().unwrap_or(0),
                ))
            });
            self.notebook.add(text, ev);
        }

        // Seed host tags
        for (ip, tags) in scenario::host_tags() {
            for tag in tags {
                core.hosts.seed_tags(ip, std::iter::once(tag.to_string()));
            }
        }

        // ── TLS Analysis tab ─────────────────────────────────────────────────
        for session in scenario::tls_sessions() {
            core.tls_tracker.insert(session);
        }

        // ── Security tab ─────────────────────────────────────────────────────
        let sec = scenario::security_seed();
        core.security.ids_alerts.extend(sec.ids_alerts);
        core.security.arp_anomalies.extend(sec.arp_anomalies);
        for g in sec.os_guesses {
            core.security.os_guesses.push(g);
        }
        core.security.vuln_hits.extend(sec.vuln_hits);
        core.security.brute_force.extend(sec.brute_force);
        core.security.http_records.extend(sec.http_records);
        core.security.tls_weaknesses.extend(sec.tls_weaknesses);
        core.security.dns_suspects.extend(sec.dns_suspects);

        // ── Credentials sub-tab ──────────────────────────────────────────────
        core.credentials.extend(scenario::credentials());
        core.security.cred_hit_count = core.credentials.len();

        // ── Objects tab ──────────────────────────────────────────────────────
        core.carved_objects.extend(scenario::carved_objects());

        // ── Rules tab ────────────────────────────────────────────────────────
        for (rule, _hits) in scenario::rules() {
            core.rule_engine.add_rule(rule);
        }
        // Fire rules against the already-ingested packets so hit counts are live
        let pkts2: Vec<_> = self.packets.iter().cloned().collect();
        for pkt in &pkts2 {
            core.rule_engine.evaluate(pkt);
        }

        core.rebuild_retained_graph(self.packets.iter());
        self.set_status("Scenario loaded: Operation Quiet Beacon — all tabs populated");
    }

    // ─── Test helpers ────────────────────────────────────────────────────────

    /// Construct an App pre-configured for tests (no terminal, no capture).
    pub fn new_for_test() -> App {
        let (tx, _rx) = tokio::sync::mpsc::channel(1024);
        let mut app = App::new(tx);
        app.picking_iface = false;
        app.selected_iface = "simulated".to_string();
        app.active_tab = Tab::Packets;
        app.auto_scroll = false;
        app.preferred_workspace = Workspace::Traffic;
        app.configure_core(|core| core.alert_center.automation_mode = AutomationMode::Off);
        app.persist_preferences = false;
        app.evidence_vault.enabled = false;
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
        self.save_preferences();
    }
}
