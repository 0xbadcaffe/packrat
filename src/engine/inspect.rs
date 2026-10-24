use super::*;

impl AnalysisCore {
    pub fn analyze_with_history<I>(&mut self, pkt: &Packet, history: I) -> PacketAnalysis
    where
        I: Iterator<Item = Packet> + Clone,
    {
        let disposition = Self::disposition(pkt);
        if disposition != PacketDisposition::Analyzed {
            return PacketAnalysis {
                disposition,
                ..Default::default()
            };
        }
        let mut notices = Vec::new();
        self.flow_tracker.update(pkt);

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
        let findings = self.security.inspect(pkt);
        for alert in &findings.ids {
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
        for anomaly in &findings.arp {
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
        for hit in &findings.vulnerabilities {
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
        for alert in &findings.authentication {
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
        for weakness in &findings.tls {
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
        let critical_ids: Vec<(String, String)> = findings
            .ids
            .iter()
            .filter(|alert| matches!(alert.severity, crate::net::security::Severity::Critical))
            .map(|alert| (alert.signature.to_string(), alert.detail.clone()))
            .collect();

        // Host inventory
        self.hosts.update(pkt);

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
        self.streams.ingest(pkt);

        // Timeline
        self.timeline.ingest(pkt);

        // TLS intelligence
        self.tls_tracker.ingest(pkt);
        self.quic_scope.ingest(pkt);

        // VLAN intelligence
        let vlan_before = self.vlan_intel.alerts.len();
        self.vlan_intel.ingest(pkt);
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
        self.ioc_engine.check_packet(pkt);
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
        self.rule_engine.evaluate(pkt);
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
            let id = self.incidents.open_or_update(
                IncidentSource::IndustrySignature,
                &signature,
                &detail,
                EvidenceSeverity::Critical,
                pkt,
                history.clone(),
            );
            notices.push(IncidentNotice {
                id,
                label: signature,
                auto_contain_rule: false,
            });
        }
        for (rule_id, rule_name, message, auto_contain) in critical_rule_hits {
            let id = self.incidents.open_or_update(
                IncidentSource::UserRule,
                &rule_id,
                format!("{rule_name}: {message}"),
                EvidenceSeverity::Critical,
                pkt,
                history.clone(),
            );
            notices.push(IncidentNotice {
                id,
                label: rule_name,
                auto_contain_rule: auto_contain,
            });
        }
        self.incidents.retain_packet(pkt);

        // Credential extraction
        let new_creds = crate::net::inspector::extract_credentials(pkt);
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

        PacketAnalysis {
            disposition,
            incidents: notices,
            alert_pins: self.alert_center.drain_pending_pins(),
        }
    }
}
