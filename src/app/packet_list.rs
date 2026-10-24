use super::*;

impl App {
    pub fn toggle_capture(&mut self) {
        self.capturing = !self.capturing;
    }

    pub fn clear_packets(&mut self) {
        self.capturing = false;
        self.packets.clear();
        self.packet_index_base = 0;
        self.filtered.clear();
        self.selected = None;
        self.worklist = InvestigationTray::default();
        self.investigation_scroll = 0;
        self.reset_header_focus();
        self.total_bytes = 0;
        self.packet_counter = 0;
        self.flow_tracker.clear();
        self.flows_selected = None;
        self.stream_overlay = None;
        self.packet_comparison = None;
        self.security.clear();
        self.alert_center.clear();
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
        self.live_response_eligible = true;
        self.processing_live_packet = false;
        self.live_response_incidents.clear();
        self.evidence_vault.clear_session();
        self.socket_scope.traffic.clear();
        self.route_ledger.clear_session();
        self.traffic_latch.clear_session();
        self.response_preview.clear();
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
            if let Some(error) = self
                .pcap_writer
                .as_mut()
                .and_then(|writer| writer.flush().err())
            {
                self.set_status(format!("Recording flush failed: {error}"));
            }
            self.pcap_writer = None;
            self.recording = false;
        } else {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let filename = format!("packrat_{}.pcapng", ts);
            // Try CWD first, then home directory as fallback.
            let candidates = [
                filename.clone(),
                dirs_next::home_dir()
                    .map(|h| h.join(&filename).to_string_lossy().into_owned())
                    .unwrap_or_else(|| format!("/tmp/{}", filename)),
            ];
            for path in &candidates {
                if let Ok(writer) = PcapNgWriter::create(std::path::Path::new(path)) {
                    self.pcap_path = path.clone();
                    self.pcap_writer = Some(writer);
                    self.recording = true;
                    break;
                }
            }
            if !self.recording {
                self.set_status("Cannot create recording: no writable output path");
            }
        }
    }

    pub fn rebuild_filtered(&mut self) {
        // Sync the AST-based display filter from the input text
        self.display_filter.set(self.filter.input.clone());

        self.filtered = self
            .packets
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                Self::packet_matches_filter(&self.display_filter, &self.filter.input, p)
            })
            .map(|(i, _)| self.packet_index_base.saturating_add(i))
            .collect();
        if let Some(sel) = self.selected {
            if sel >= self.filtered.len() {
                self.selected = if self.filtered.is_empty() {
                    None
                } else {
                    Some(self.filtered.len() - 1)
                };
            }
        }
    }

    pub(super) fn packet_matches_filter(
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
        self.selected
            .and_then(|i| self.filtered.get(i))
            .and_then(|&index| self.retained_packet_at(index))
    }

    pub fn retained_packet_at(&self, index: usize) -> Option<&Packet> {
        self.packets.get(index.checked_sub(self.packet_index_base)?)
    }
}
