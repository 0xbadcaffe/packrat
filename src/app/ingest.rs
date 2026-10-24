use super::*;

impl App {
    pub fn ingest_packet(&mut self, pkt: Packet) {
        if let Err(error) = self.try_ingest_packet(pkt) {
            self.reject_analysis_packet(error);
        }
    }

    pub fn try_ingest_packet(&mut self, pkt: Packet) -> Result<(), SubmitError<Packet>> {
        if !self.capturing {
            return Ok(());
        }
        if self.analysis_backpressured() {
            return Err(SubmitError::Full(pkt));
        }
        let live = self.selected_iface != "simulated"
            && pkt.capture.as_ref().is_some_and(|capture| {
                capture.timestamp.is_some()
                    && capture.interface_name.as_deref() == Some(self.selected_iface.as_str())
            });
        self.try_analyze_packet(pkt, live, self.restoring_project)
    }

    /// Inject a packet regardless of capturing state (used by packet crafter).
    pub fn inject_packet(&mut self, pkt: Packet) {
        self.ingest_packet_inner(pkt);
    }

    pub(super) fn ingest_packet_inner(&mut self, pkt: Packet) {
        if self.analysis_worker.is_some() {
            if let Err(error) = self.enqueue_offline_packets(vec![pkt], self.restoring_project) {
                self.set_status(error);
            }
            return;
        }
        self.analyze_packet(pkt, false);
    }

    pub(super) fn analyze_packet(&mut self, pkt: Packet, live: bool) {
        if let Err(error) = self.try_analyze_packet(pkt, live, self.restoring_project) {
            self.reject_analysis_packet(error);
        }
    }

    pub(super) fn try_analyze_packet(
        &mut self,
        pkt: Packet,
        live: bool,
        restoring: bool,
    ) -> Result<(), SubmitError<Packet>> {
        if let Some(worker) = &mut self.analysis_worker {
            match worker.try_packet(pkt.clone(), live) {
                Ok(sequence) => {
                    self.packet_effects.insert(sequence, restoring);
                }
                Err(SubmitError::Full(_)) => return Err(SubmitError::Full(pkt)),
                Err(SubmitError::Disconnected(_)) => return Err(SubmitError::Disconnected(pkt)),
                Err(SubmitError::Oversized(_)) => return Err(SubmitError::Oversized(pkt)),
            }
        }
        if !live {
            // Offline traffic shares detector state with the live view. Once
            // mixed, require a clean session before allowing host enforcement.
            self.live_response_eligible = false;
            self.live_response_incidents.clear();
        }
        self.processing_live_packet = live && self.live_response_eligible;
        if let Some(error) = self
            .packet_archive
            .as_ref()
            .filter(|_| !restoring)
            .and_then(|archive| archive.record(&pkt).err())
        {
            self.abort_capture();
            self.capturing = false;
            self.set_status(format!("Capture stopped: {error}"));
        }
        self.packet_counter += 1;
        self.total_bytes += pkt.length as u64;
        self.rate_this_sec += 1;
        if pkt
            .capture
            .as_ref()
            .is_some_and(|capture| capture.link_type != 1 || capture.timestamp.is_none())
        {
            self.retain_analyzed_display(pkt, restoring);
            return Ok(());
        }
        let process = self.socket_scope.observe(&pkt);
        self.route_ledger.observe(&pkt, process.as_deref());
        self.wire_pulse.observe(&pkt);
        self.net_registry.observe(&pkt.src);
        self.net_registry.observe(&pkt.dst);
        if self.analysis_worker.is_none() {
            let analysis = self
                .core
                .edit()
                .analyze_with_history(&pkt, self.packets.iter().cloned());
            if let Some(context) = self.analysis_context(&analysis) {
                self.handle_packet_analysis(analysis, context, live, restoring);
            }
        }
        self.retain_analyzed_display(pkt, restoring);
        Ok(())
    }

    fn retain_analyzed_display(&mut self, pkt: Packet, restoring: bool) {
        let previous = self.restoring_project;
        self.restoring_project = restoring;
        self.retain_packet_display(pkt);
        self.restoring_project = previous;
    }

    pub(super) fn retain_packet_display(&mut self, pkt: Packet) {
        if self.recording && !self.restoring_project {
            if let Some(error) = self
                .pcap_writer
                .as_mut()
                .and_then(|writer| writer.write_packet(&pkt).err())
            {
                self.recording = false;
                self.pcap_writer.take();
                self.set_status(format!("Recording stopped: {error}"));
            }
        }

        if self.display_filter.input != self.filter.input {
            self.display_filter.set(self.filter.input.clone());
        }

        if Self::packet_matches_filter(&self.display_filter, &self.filter.input, &pkt) {
            self.filtered
                .push_back(self.packet_index_base.saturating_add(self.packets.len()));
            if self.auto_scroll {
                self.selected = Some(self.filtered.len().saturating_sub(1));
            } else if self.selected.is_none() {
                self.selected = Some(0);
            }
        }

        self.packets.push_back(pkt);
        if self.packets.len() > MAX_PACKETS {
            self.packets.pop_front();
            self.packet_index_base = self.packet_index_base.saturating_add(1);
            let stale = self
                .filtered
                .partition_point(|index| *index < self.packet_index_base);
            if stale > 0 {
                self.filtered.drain(..stale);
                self.selected = self.selected.map(|selected| selected.saturating_sub(stale));
            }
        }
    }
}
