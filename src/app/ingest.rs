use super::*;

impl App {
    pub fn ingest_packet(&mut self, pkt: Packet) {
        if !self.capturing {
            return;
        }
        let live = self.selected_iface != "simulated"
            && pkt.capture.as_ref().is_some_and(|capture| {
                capture.timestamp.is_some()
                    && capture.interface_name.as_deref() == Some(self.selected_iface.as_str())
            });
        self.analyze_packet(pkt, live);
    }

    /// Inject a packet regardless of capturing state (used by packet crafter).
    pub fn inject_packet(&mut self, pkt: Packet) {
        self.ingest_packet_inner(pkt);
    }

    pub(super) fn ingest_packet_inner(&mut self, pkt: Packet) {
        self.analyze_packet(pkt, false);
    }

    pub(super) fn analyze_packet(&mut self, pkt: Packet, live: bool) {
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
            .filter(|_| !self.restoring_project)
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
            self.retain_packet_display(pkt);
            return;
        }
        self.flow_tracker.update(&pkt);
        let process = self.socket_scope.observe(&pkt);
        self.route_ledger.observe(&pkt, process.as_deref());
        self.wire_pulse.observe(&pkt);
        self.net_registry.observe(&pkt.src);
        self.net_registry.observe(&pkt.dst);

        // Graph ingestion — extract before pkt is moved
        self.operator_graph.on_packet(
            &pkt.src,
            &pkt.dst,
            &pkt.protocol,
            pkt.src_port,
            pkt.dst_port,
            pkt.timestamp,
            pkt.length as u64,
            pkt.no,
        );

        // Security analysis. Critical built-in signatures open an incident for
        // explicit operator review; lower severities remain in the Security tab.
        let ids_before = self.security.ids_alerts.len();
        let arp_before = self.security.arp_anomalies.len();
        let vuln_before = self.security.vuln_hits.len();
        let brute_before = self.security.brute_force.len();
        let tls_before = self.security.tls_weaknesses.len();
        let is_dns = pkt.protocol.eq_ignore_ascii_case("DNS")
            || pkt.src_port == Some(53)
            || pkt.dst_port == Some(53);
        let dns_before: std::collections::HashMap<String, u64> = if is_dns {
            self.security
                .dns_suspects
                .iter()
                .map(|suspect| (suspect.apex.clone(), suspect.query_count))
                .collect()
        } else {
            std::collections::HashMap::new()
        };
        self.security.update(&pkt);
        for alert in &self.security.ids_alerts[ids_before..] {
            self.alert_center.record_correlated(
                alert.pkt_no,
                pkt.timestamp,
                "IDS",
                alert.severity.to_string(),
                alert.signature,
                &alert.detail,
                format!("{}>{}", pkt.src, pkt.dst),
            );
        }
        for anomaly in &self.security.arp_anomalies[arp_before..] {
            self.alert_center.record_correlated(
                anomaly.pkt_no,
                pkt.timestamp,
                "ARP",
                "HIGH",
                "ARP binding changed",
                format!(
                    "{} moved from {} to {}",
                    anomaly.ip, anomaly.old_mac, anomaly.new_mac
                ),
                &anomaly.ip,
            );
        }
        for hit in &self.security.vuln_hits[vuln_before..] {
            self.alert_center.record_correlated(
                hit.pkt_no,
                pkt.timestamp,
                "EXPOSURE",
                "HIGH",
                hit.kind,
                &hit.detail,
                format!("{}>{}", pkt.src, pkt.dst),
            );
        }
        for alert in &self.security.brute_force[brute_before..] {
            self.alert_center.record_correlated(
                pkt.no,
                pkt.timestamp,
                "AUTH",
                "HIGH",
                format!("{} authentication burst", alert.service),
                format!(
                    "{} attempts from {} to {}:{}",
                    alert.attempts, alert.src_ip, alert.dst_ip, alert.port
                ),
                format!("{}>{}:{}", alert.src_ip, alert.dst_ip, alert.port),
            );
        }
        for weakness in &self.security.tls_weaknesses[tls_before..] {
            self.alert_center.record_correlated(
                weakness.pkt_no,
                pkt.timestamp,
                "TLS",
                "MEDIUM",
                weakness.kind,
                &weakness.detail,
                format!("{}>{}", weakness.src_ip, weakness.dst_ip),
            );
        }
        for suspect in self.security.dns_suspects.iter().filter(|suspect| {
            is_dns
                && suspect.score >= 8.0
                && dns_before.get(&suspect.apex).copied().unwrap_or(0) < suspect.query_count
        }) {
            self.alert_center.record_correlated(
                pkt.no,
                pkt.timestamp,
                "DNS",
                if suspect.score > 12.0 {
                    "HIGH"
                } else {
                    "MEDIUM"
                },
                "DNS tunnel behavior",
                format!(
                    "{} queries to {}, entropy {:.2}, {} unique labels, score {:.1}",
                    suspect.query_count,
                    suspect.apex,
                    suspect.max_entropy,
                    suspect.unique_subdomains,
                    suspect.score,
                ),
                &suspect.apex,
            );
        }
        let critical_ids: Vec<(String, String)> = self.security.ids_alerts[ids_before..]
            .iter()
            .filter(|alert| matches!(alert.severity, crate::net::security::Severity::Critical))
            .map(|alert| (alert.signature.to_string(), alert.detail.clone()))
            .collect();

        // Host inventory
        self.hosts.update(&pkt);

        // Sync OS guess from security engine → host inventory
        if let Some(os) = self.security.os_guess_for(&pkt.src) {
            if self
                .hosts
                .get(&pkt.src)
                .and_then(|h| h.os_guess.as_deref())
                .is_none()
            {
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
        let vlan_before = self.vlan_intel.alerts.len();
        self.vlan_intel.ingest(&pkt);
        for alert in &self.vlan_intel.alerts[vlan_before..] {
            self.alert_center.record_correlated(
                alert.pkt_no,
                pkt.timestamp,
                "VLAN",
                alert.severity.to_string(),
                &alert.category,
                &alert.detail,
                format!("{}>{}", pkt.src, pkt.dst),
            );
        }

        // IOC matching
        let ioc_before = self.ioc_engine.hits.len();
        self.ioc_engine.check_packet(&pkt);
        for hit in &self.ioc_engine.hits[ioc_before..] {
            self.alert_center.record_correlated(
                hit.pkt_no,
                pkt.timestamp,
                "IOC",
                "HIGH",
                format!("{} match", hit.ioc.kind),
                format!(
                    "{} matched {} ({})",
                    hit.context, hit.ioc.value, hit.ioc.description
                ),
                &hit.ioc.value,
            );
        }

        // Critical alert actions in user rules share the same review workflow.
        let rule_hits_before = self.rule_engine.hits.len();
        self.rule_engine.evaluate(&pkt);
        for hit in &self.rule_engine.hits[rule_hits_before..] {
            let severity = match &hit.action {
                RuleAction::Alert { severity, .. } => severity.to_string(),
                RuleAction::Tag { .. } => "INFO".to_string(),
                RuleAction::Log { .. } => "LOW".to_string(),
            };
            self.alert_center.record_correlated(
                hit.pkt_no,
                pkt.timestamp,
                "RULE",
                severity,
                &hit.rule_name,
                &hit.message,
                format!("{}:{}>{}", hit.rule_id, pkt.src, pkt.dst),
            );
        }
        let critical_rule_hits: Vec<(String, String, String, bool)> = self.rule_engine.hits
            [rule_hits_before..]
            .iter()
            .filter(|hit| {
                matches!(
                    &hit.action,
                    RuleAction::Alert {
                        severity: EvidenceSeverity::Critical,
                        ..
                    }
                )
            })
            .map(|hit| {
                (
                    hit.rule_id.clone(),
                    hit.rule_name.clone(),
                    hit.message.clone(),
                    hit.auto_contain,
                )
            })
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
            for credential in &new_creds {
                self.alert_center.record_correlated(
                    credential.pkt_no,
                    pkt.timestamp,
                    "CREDENTIAL",
                    "HIGH",
                    credential.kind,
                    format!("Exposed credential value: {}", credential.value),
                    format!("{}:{}>{}", credential.kind, pkt.src, pkt.dst),
                );
            }
            self.credentials.extend(new_creds);
            if self.credentials.len() > 1000 {
                self.credentials.drain(0..100);
            }
        }

        for alert_id in self.alert_center.drain_pending_pins() {
            self.worklist.add(InvestigationItem::Alert(alert_id));
        }

        self.retain_packet_display(pkt);
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
                .push(self.packet_index_base.saturating_add(self.packets.len()));
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
