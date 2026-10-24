use super::*;

impl App {
    /// Inject a crafted packet into the live packet list.
    pub fn craft_inject(&mut self) {
        let next_no = self.packet_counter + 1;
        match self.craft.build_packet(next_no) {
            Ok(pkt) => {
                let label = format!(
                    "Injected #{} — {} {} → {}",
                    next_no, pkt.protocol, pkt.src, pkt.dst
                );
                self.craft.result = Some(Ok(label));
                self.inject_packet(pkt);
            }
            Err(e) => {
                self.craft.result = Some(Err(e));
            }
        }
    }

    pub fn tick(&mut self) {
        if let Some(error) = self
            .packet_archive
            .as_mut()
            .and_then(|archive| archive.poll_error())
        {
            self.abort_capture();
            self.capturing = false;
            self.set_status(format!("Capture stopped: archive write failed: {error}"));
        }
        if let Some(result) = self.capture_handle.as_mut().and_then(|task| task.result()) {
            self.capture_handle = None;
            self.capturing = false;
            self.set_status(match result {
                Ok(()) => "Capture stopped".into(),
                Err(error) => error,
            });
        }
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
        if self.scan.running {
            self.scan.tick();
        }

        if self.rate_tick % 20 == 1 {
            let _ = self.socket_scope.refresh_event_file();
            let _ = self.socket_scope.refresh();
            if self.core.tls_tracker.key_shelf.path.is_some() {
                let _ = self.core.tls_tracker.reload_key_log();
            }
        }

        // Advance PCAP replay — inject replayed packets
        let replayed = self.replay.tick();
        for pkt in replayed {
            self.ingest_packet_inner(pkt);
        }

        if self.capturing {
            if rand::random::<u8>() % 3 == 0 {
                let entry = crate::sim::dynamic::generate_entry(self.rate_tick);
                self.dyn_log.push(entry);
                if self.dyn_log.len() > 500 {
                    self.dyn_log.remove(0);
                }
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
            if self.status_msg_ticks == 0 {
                self.status_msg = None;
            }
        }

        self.core.maintenance();
        self.refresh_telemetry();
    }

    pub(crate) fn animation_tick(&self) -> u32 {
        self.rate_tick
    }

    pub(super) fn refresh_telemetry(&self) {
        self.telemetry.publish(TelemetrySnapshot {
            packets_total: self.packet_counter,
            bytes_total: self.total_bytes,
            visible_packets: self.filtered.len(),
            flows: self.core.flow_tracker.flows.len(),
            hosts: self.core.hosts.len(),
            security_findings: self.core.security.alert_count(),
            rule_hits: self.core.rule_engine.hits.len(),
            ioc_hits: self.core.ioc_engine.hit_count(),
            pending_incidents: self
                .core
                .incidents
                .incidents
                .iter()
                .filter(|incident| {
                    incident.status == crate::analysis::incident::IncidentStatus::PendingReview
                })
                .count(),
            evidence_exports: self.evidence_vault.exports.len(),
            packets_per_second: self.current_rate(),
            capturing: self.capturing,
            latency_p95_ms: self.wire_pulse.p95_ms().unwrap_or(0.0),
            enriched_addresses: self.net_registry.observed.len(),
        });
    }

}
