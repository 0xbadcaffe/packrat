use super::*;

impl App {
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
        for index in 0..Tab::COUNT {
            let view = Tab::from_index(index);
            let aliases = match view {
                Tab::Security => "alerts detections security",
                Tab::Scanner => "scan scanner service discovery",
                Tab::Traceroute => "traceroute network path",
                Tab::Craft => "craft packet generator",
                Tab::TlsAnalysis => "tls dtls quic encrypted",
                _ => "",
            };
            let label = format!("Open {}", view.label());
            if q.is_empty() || format!("{label} {aliases}").to_lowercase().contains(&q) {
                results.push(SearchResult {
                    packet_no: None,
                    source: "View",
                    label,
                    detail: view.workspace().label().into(),
                    jump_tab: view,
                    scroll: 0,
                });
            }
        }
        let mut packet_results = 0;

        // ── Packets ──────────────────────────────────────────────────────────
        for (idx, pkt) in self.packets.iter().enumerate().take(500) {
            let label = format!("#{} {} → {} [{}]", pkt.no, pkt.src, pkt.dst, pkt.protocol);
            let detail = pkt.info.clone();
            let haystack = format!(
                "{} {} {} {}",
                label,
                detail,
                pkt.src_port.map_or_else(String::new, |p| p.to_string()),
                pkt.dst_port.map_or_else(String::new, |p| p.to_string())
            )
            .to_lowercase();
            if q.is_empty() || haystack.contains(&q) {
                results.push(SearchResult {
                    packet_no: Some(pkt.no),
                    source: "Packet",
                    label,
                    detail,
                    jump_tab: Tab::Packets,
                    scroll: idx,
                });
                packet_results += 1;
                if packet_results >= 20 {
                    break;
                }
            }
        }

        // ── Hosts ─────────────────────────────────────────────────────────────
        let host_list: Vec<_> = self.hosts.all().into_iter().enumerate().collect();
        for (idx, host) in host_list {
            let label = host.ip.clone();
            let detail = format!(
                "pkts:{} bytes:{}",
                host.pkts_out + host.pkts_in,
                host.bytes_out + host.bytes_in
            );
            let haystack = format!("{} {}", label, detail).to_lowercase();
            if q.is_empty() || haystack.contains(&q) {
                results.push(SearchResult {
                    packet_no: None,
                    source: "Host",
                    label,
                    detail,
                    jump_tab: Tab::Hosts,
                    scroll: idx,
                });
                if results.iter().filter(|r| r.source == "Host").count() >= 10 {
                    break;
                }
            }
        }

        // ── IOC hits ──────────────────────────────────────────────────────────
        for (idx, hit) in self.ioc_engine.hits.iter().enumerate() {
            let label = format!("{} {}", hit.ioc.kind, hit.ioc.value);
            let detail = hit.context.clone();
            let haystack = format!("{} {}", label, detail).to_lowercase();
            if q.is_empty() || haystack.contains(&q) {
                results.push(SearchResult {
                    packet_no: None,
                    source: "IOC Hit",
                    label,
                    detail,
                    jump_tab: Tab::Security,
                    scroll: idx,
                });
                if results.iter().filter(|r| r.source == "IOC Hit").count() >= 10 {
                    break;
                }
            }
        }

        // ── Rule hits ─────────────────────────────────────────────────────────
        for (idx, hit) in self.rule_engine.hits.iter().enumerate() {
            let label = hit.rule_name.clone();
            let detail = hit.message.clone();
            let haystack = format!("{} {}", label, detail).to_lowercase();
            if q.is_empty() || haystack.contains(&q) {
                results.push(SearchResult {
                    packet_no: None,
                    source: "Rule Hit",
                    label,
                    detail,
                    jump_tab: Tab::Rules,
                    scroll: idx,
                });
                if results.iter().filter(|r| r.source == "Rule Hit").count() >= 10 {
                    break;
                }
            }
        }

        // ── YARA matches ──────────────────────────────────────────────────────
        for (idx, result) in self.yara_engine.results.iter().enumerate() {
            let label = result.target_label.clone();
            let detail = result.rule_names().join(", ");
            let haystack = format!("{} {}", label, detail).to_lowercase();
            if q.is_empty() || haystack.contains(&q) {
                results.push(SearchResult {
                    packet_no: None,
                    source: "YARA",
                    label,
                    detail,
                    jump_tab: Tab::Objects,
                    scroll: idx,
                });
                if results.iter().filter(|r| r.source == "YARA").count() >= 10 {
                    break;
                }
            }
        }

        // ── Carved objects ────────────────────────────────────────────────────
        for (idx, obj) in self.carved_objects.iter().enumerate() {
            let label = format!("#{} {}", obj.id, obj.kind);
            let detail = obj.source.clone();
            let haystack = format!("{} {} {}", label, detail, obj.sha256).to_lowercase();
            if q.is_empty() || haystack.contains(&q) {
                results.push(SearchResult {
                    packet_no: None,
                    source: "Object",
                    label,
                    detail,
                    jump_tab: Tab::Objects,
                    scroll: idx,
                });
                if results.iter().filter(|r| r.source == "Object").count() >= 10 {
                    break;
                }
            }
        }

        self.search_results = results;
        self.search_selected = self
            .search_selected
            .min(self.search_results.len().saturating_sub(1));
    }

    /// Apply the currently selected search result (navigate to it).
    pub fn search_jump(&mut self) {
        if let Some(result) = self.search_results.get(self.search_selected).cloned() {
            if result.source == "View" {
                self.navigate_to(result.jump_tab);
                self.close_search();
                return;
            }
            if let Some(no) = result.packet_no {
                let Some(index) = self.packets.iter().position(|packet| packet.no == no) else {
                    self.set_status(format!(
                        "Packet #{no} is no longer retained in the live window"
                    ));
                    self.close_search();
                    return;
                };
                let absolute = self.packet_index_base.saturating_add(index);
                if !self.filtered.contains(&absolute) {
                    self.filter.input.clear();
                    self.rebuild_filtered();
                }
                self.selected = self.filtered.iter().position(|entry| *entry == absolute);
                self.navigate_to(Tab::Packets);
                self.close_search();
                return;
            }
            self.navigate_to(result.jump_tab);
            // Apply scroll hints depending on destination
            match result.jump_tab {
                Tab::Packets => {
                    self.selected = Some(result.scroll);
                }
                Tab::Hosts => {
                    self.hosts_scroll = result.scroll;
                }
                Tab::Rules => {
                    self.rules_scroll = result.scroll;
                }
                Tab::Objects => {
                    self.objects_scroll = result.scroll;
                }
                Tab::Security => {
                    self.security_scroll = result.scroll;
                }
                _ => {}
            }
        }
        self.close_search();
    }
}
