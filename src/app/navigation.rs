use super::*;

impl App {
    pub fn current_rate(&self) -> u32 {
        *self.rate_history.last().unwrap_or(&0)
    }

    pub fn move_down(&mut self) {
        match self.active_tab {
            Tab::Packets => {
                if let Some(sel) = self.selected {
                    if sel + 1 < self.filtered.len() {
                        self.selected = Some(sel + 1);
                    }
                } else if !self.filtered.is_empty() {
                    self.selected = Some(0);
                }
            }
            Tab::Investigate => self.investigation_scroll_down(),
            Tab::Analysis => {
                if self.analysis_section < INCIDENT_ANALYSIS_SECTION {
                    self.analysis_section += 1;
                }
            }
            // j = toward tail (decrease offset-from-end)
            Tab::Dynamic => {
                self.dyn_scroll = self.dyn_scroll.saturating_sub(1);
            }
            Tab::Flows => {
                let len = self.core.flow_tracker.flows.len();
                if let Some(sel) = self.flows_selected {
                    if sel + 1 < len {
                        self.flows_selected = Some(sel + 1);
                    }
                } else if len > 0 {
                    self.flows_selected = Some(0);
                }
            }
            _ => {}
        }
    }

    pub fn move_up(&mut self) {
        match self.active_tab {
            Tab::Packets => {
                if let Some(sel) = self.selected {
                    if sel > 0 {
                        self.selected = Some(sel - 1);
                    }
                }
            }
            Tab::Investigate => self.investigation_scroll_up(),
            Tab::Analysis => {
                if self.analysis_section > 0 {
                    self.analysis_section -= 1;
                }
            }
            // k = away from tail (increase offset-from-end), clamped to log length
            Tab::Dynamic => {
                let max = self.dyn_log.len().saturating_sub(1);
                if self.dyn_scroll < max {
                    self.dyn_scroll += 1;
                }
            }
            Tab::Flows => {
                if let Some(sel) = self.flows_selected {
                    if sel > 0 {
                        self.flows_selected = Some(sel - 1);
                    }
                }
            }
            _ => {}
        }
    }

    pub fn flows_sort_bytes(&mut self) {
        self.flows_sort = FlowSort::Bytes;
    }
    pub fn flows_sort_packets(&mut self) {
        self.flows_sort = FlowSort::Packets;
    }
    pub fn flows_sort_time(&mut self) {
        self.flows_sort = FlowSort::Time;
    }
    pub fn flows_sort_beacon(&mut self) {
        self.flows_sort = FlowSort::BeaconScore;
    }

    pub fn flows_open_stream(&mut self) {
        let sorted = self.core.flow_tracker.sorted_flows(&self.flows_sort);
        let stream_id = self
            .flows_selected
            .and_then(|index| sorted.get(index))
            .and_then(|flow| {
                self.packets
                    .iter()
                    .find(|packet| FlowKey::from_packet(packet) == flow.key)
                    .and_then(StreamKey::from_packet)
                    .map(|key| key.id())
            });
        let Some(stream_id) = stream_id else {
            self.set_status("Selected flow has no retained TCP packet context");
            return;
        };
        self.open_reassembled_stream(stream_id);
    }

    pub fn flows_jump_to_packets(&mut self) {
        let sorted = self.core.flow_tracker.sorted_flows(&self.flows_sort);
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
            self.selected = if self.filtered.is_empty() {
                None
            } else {
                Some(0)
            };
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
            if let Some(sel) = self.selected {
                self.selected = Some(sel.saturating_sub(10));
            }
        }
    }

    pub fn next_tab(&mut self) {
        let views = self.active_tab.workspace().views();
        let current = views
            .iter()
            .position(|view| *view == self.active_tab)
            .unwrap_or(0);
        self.active_tab = views[(current + 1) % views.len()];
    }

    pub fn prev_tab(&mut self) {
        let views = self.active_tab.workspace().views();
        let current = views
            .iter()
            .position(|view| *view == self.active_tab)
            .unwrap_or(0);
        self.active_tab = views[if current == 0 {
            views.len() - 1
        } else {
            current - 1
        }];
    }

    pub fn select_workspace(&mut self, workspace: Workspace) {
        self.navigate_to(workspace.home());
        self.view_menu_open = false;
        self.view_menu_cursor = 0;
    }

    pub fn navigate_to(&mut self, destination: Tab) {
        if destination == self.active_tab {
            return;
        }
        self.navigation_history.push(self.active_tab);
        if self.navigation_history.len() > 32 {
            self.navigation_history.remove(0);
        }
        self.active_tab = destination;
    }

    pub fn navigate_back(&mut self) -> bool {
        let Some(previous) = self.navigation_history.pop() else {
            return false;
        };
        self.active_tab = previous;
        self.view_menu_open = false;
        true
    }

    pub fn open_view_menu(&mut self) {
        let views = self.active_tab.workspace().views();
        self.view_menu_cursor = views
            .iter()
            .position(|view| *view == self.active_tab)
            .unwrap_or(0);
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
        if let Some(view) = self
            .active_tab
            .workspace()
            .views()
            .get(self.view_menu_cursor)
        {
            self.navigate_to(*view);
        }
        self.view_menu_open = false;
    }

    /// Return through screen history, falling back to the workspace home.
    pub fn return_to_workspace_home(&mut self) -> bool {
        if self.navigate_back() {
            return true;
        }
        if self.active_tab.is_workspace_home() {
            return false;
        }
        self.active_tab = self.active_tab.workspace().home();
        true
    }

    pub fn security_subtab_next(&mut self) {
        self.security_tab = match self.security_tab {
            SecuritySubTab::Alerts => SecuritySubTab::ProcessScope,
            SecuritySubTab::Ids => SecuritySubTab::Credentials,
            SecuritySubTab::Credentials => SecuritySubTab::OsFingerprint,
            SecuritySubTab::OsFingerprint => SecuritySubTab::ArpWatch,
            SecuritySubTab::ArpWatch => SecuritySubTab::DnsTunnel,
            SecuritySubTab::DnsTunnel => SecuritySubTab::HttpAnalytics,
            SecuritySubTab::HttpAnalytics => SecuritySubTab::TlsWeakness,
            SecuritySubTab::TlsWeakness => SecuritySubTab::BruteForce,
            SecuritySubTab::BruteForce => SecuritySubTab::VulnHits,
            SecuritySubTab::VulnHits => SecuritySubTab::IocHits,
            SecuritySubTab::IocHits => SecuritySubTab::VlanIntel,
            SecuritySubTab::VlanIntel => SecuritySubTab::ProcessScope,
            SecuritySubTab::ProcessScope => SecuritySubTab::RoutePolicy,
            SecuritySubTab::RoutePolicy => SecuritySubTab::WirePulse,
            SecuritySubTab::WirePulse => SecuritySubTab::NetRegistry,
            SecuritySubTab::NetRegistry => SecuritySubTab::Replay,
            SecuritySubTab::Replay => SecuritySubTab::Alerts,
        };
    }

    pub fn security_subtab_prev(&mut self) {
        self.security_tab = match self.security_tab {
            SecuritySubTab::Alerts => SecuritySubTab::Replay,
            SecuritySubTab::Ids => SecuritySubTab::Alerts,
            SecuritySubTab::Credentials => SecuritySubTab::Ids,
            SecuritySubTab::OsFingerprint => SecuritySubTab::Credentials,
            SecuritySubTab::ArpWatch => SecuritySubTab::OsFingerprint,
            SecuritySubTab::DnsTunnel => SecuritySubTab::ArpWatch,
            SecuritySubTab::HttpAnalytics => SecuritySubTab::DnsTunnel,
            SecuritySubTab::TlsWeakness => SecuritySubTab::HttpAnalytics,
            SecuritySubTab::BruteForce => SecuritySubTab::TlsWeakness,
            SecuritySubTab::VulnHits => SecuritySubTab::BruteForce,
            SecuritySubTab::IocHits => SecuritySubTab::VulnHits,
            SecuritySubTab::VlanIntel => SecuritySubTab::IocHits,
            SecuritySubTab::ProcessScope => SecuritySubTab::VlanIntel,
            SecuritySubTab::RoutePolicy => SecuritySubTab::ProcessScope,
            SecuritySubTab::WirePulse => SecuritySubTab::RoutePolicy,
            SecuritySubTab::NetRegistry => SecuritySubTab::WirePulse,
            SecuritySubTab::Replay => SecuritySubTab::NetRegistry,
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
        match self.core.tls_tracker.load_key_log(path.as_ref()) {
            Ok(count) => self.set_status(format!("Loaded {count} TLS/QUIC key-log secrets")),
            Err(error) => self.set_status(format!("Key-log error: {error}")),
        }
    }

    pub fn refresh_selected_whois(&mut self) {
        let address = self
            .net_registry
            .sorted()
            .get(self.security_scroll)
            .map(|entry| entry.address);
        let Some(address) = address else {
            self.set_status("No address selected for refresh");
            return;
        };
        if let Some(path) = self.reputation_helper_path.clone() {
            match self
                .net_registry
                .refresh_reputation_with_helper(address, path)
            {
                Ok(identity) => {
                    let detail = identity
                        .reputation
                        .as_ref()
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
            EncryptedView::Tls => self
                .core
                .tls_tracker
                .all()
                .get(self.tls_selected)
                .and_then(|session| session.ja4.clone()),
            EncryptedView::Quic => self
                .core
                .quic_scope
                .all()
                .get(self.tls_selected)
                .map(|connection| connection.ratq.clone()),
        };
        let Some(fingerprint) = fingerprint.filter(|value| !value.is_empty()) else {
            self.set_status("No selected encrypted fingerprint to refresh");
            return;
        };
        match self
            .net_registry
            .refresh_fingerprint_reputation_with_helper(&fingerprint, path)
        {
            Ok(finding) => self.set_status(format!(
                "Reputation {fingerprint}: {} ({})",
                finding.label, finding.severity,
            )),
            Err(error) => self.set_status(format!("Reputation error: {error}")),
        }
    }
}
