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
            if self.tls_tracker.key_shelf.path.is_some() {
                let _ = self.tls_tracker.reload_key_log();
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

        self.yara_scan_new_objects();
        self.graph_tick();
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
            flows: self.flow_tracker.flows.len(),
            hosts: self.hosts.len(),
            security_findings: self.security.alert_count(),
            rule_hits: self.rule_engine.hits.len(),
            ioc_hits: self.ioc_engine.hit_count(),
            pending_incidents: self
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

    /// Incrementally sync all analysis subsystems into the operator graph,
    /// then recompute scores / paths / clusters on a throttled schedule.
    pub(super) fn graph_tick(&mut self) {
        self.graph_tick_counter = self.graph_tick_counter.wrapping_add(1);

        // ── Sync IDS alerts ──────────────────────────────────────────────────
        let new_alerts = self.security.ids_alerts.len();
        if new_alerts > self.graph_ui.synced_alerts {
            for alert in &self.security.ids_alerts[self.graph_ui.synced_alerts..new_alerts] {
                self.operator_graph.on_ids_alert(
                    alert.signature,
                    &alert.severity.to_string(),
                    "", // IdsAlert doesn't carry src/dst IP here — use empty
                    "",
                    alert.pkt_no,
                    0.0, // no timestamp on IdsAlert
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
}
