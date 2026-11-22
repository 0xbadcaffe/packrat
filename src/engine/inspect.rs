use super::*;
use crate::analysis::alert_center::AlertFlow;

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
        self.streams.ingest(pkt);
        let modbus = self.streams.observe_modbus(pkt);
        let findings = self.security.inspect_with_modbus(pkt, modbus);
        for finding in &findings.ids {
            let alert = &finding.alert;
            self.operator_graph.on_ids_alert(
                alert.signature,
                &alert.severity.to_string(),
                &pkt.src,
                &pkt.dst,
                alert.pkt_no,
                pkt.timestamp,
            );
            let flow = if matches!(alert.signature,
                "Periodic fixed-size traffic" | "TCP payload after reset" | "Conflicting TCP retransmission"
                | "Industrial state-changing command" | "Critical industrial control command"
                | "Cleartext HTTP Basic authorization"
            ) {
                AlertFlow::from_packet(pkt)
            } else {
                None
            };
            self.alert_center.record_with_context(
                (alert.pkt_no, &finding.related_packets, flow),
                pkt.timestamp,
                "IDS",
                alert.severity.to_string(),
                alert.signature,
                &alert.detail,
                finding
                    .correlation_key
                    .clone()
                    .unwrap_or_else(|| format!("{}>{}", pkt.src, pkt.dst)),
            );
        }
        for finding in &findings.arp {
            let anomaly = &finding.anomaly;
            self.alert_center.record_correlated_with_evidence(
                (anomaly.pkt_no, &[finding.previous_frame]),
                pkt.timestamp,
                "ARP",
                "MEDIUM",
                "ARP binding changed",
                format!(
                    "ARP replies for {} claimed {} and then {}; whether any host accepted the change is unknown",
                    anomaly.ip, anomaly.old_mac, anomaly.new_mac
                ),
                &finding.correlation_key,
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
            let (severity, title, observation) = match alert.service {
                "SSH" => (
                    "MEDIUM",
                    "SSH connection-start burst".into(),
                    "distinct TCP SYNs (authentication outcome not observable)",
                ),
                "HTTP" => ("MEDIUM", "HTTP authentication burst".into(), "HTTP 401 responses"),
                "FTP" => ("MEDIUM", "FTP not-logged-in reply burst".into(), "FTP 530 replies"),
                "SMB" => ("MEDIUM", "SMB2 logon failure burst".into(), "SMB2 SESSION_SETUP logon failures"),
                service => ("HIGH", format!("{service} authentication burst"), "attempts"),
            };
            let scope = (
                pkt.capture.as_ref().map(|c| (c.section_id, c.interface_id)),
                pkt.outer_vlan_id,
                pkt.vlan_id,
            );
            self.alert_center.record_correlated_with_evidence(
                (pkt.no, &alert.packet_refs),
                pkt.timestamp,
                "AUTH",
                severity,
                title,
                format!(
                    "{} {observation} for client {} and service {}:{}",
                    alert.attempts, alert.src_ip, alert.dst_ip, alert.port
                ),
                format!("{scope:?}:{}>{}:{}", alert.src_ip, alert.dst_ip, alert.port),
            );
        }
        for weakness in &findings.tls {
            let scope = (
                pkt.capture.as_ref().map(|c| (c.section_id, c.interface_id)),
                pkt.outer_vlan_id,
                pkt.vlan_id,
            );
            self.alert_center.record_with_context(
                (weakness.pkt_no, &[], AlertFlow::from_packet(pkt)),
                pkt.timestamp,
                "TLS",
                "MEDIUM",
                weakness.kind,
                &weakness.detail,
                format!("{scope:?}:{}:{}>{}:{}", weakness.src_ip, pkt.src_port.unwrap_or(0),
                    weakness.dst_ip, pkt.dst_port.unwrap_or(0)),
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
            .map(|finding| &finding.alert)
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

        // Timeline
        self.timeline.ingest(pkt);

        // TLS intelligence
        self.tls_tracker.ingest(pkt);
        self.quic_scope.ingest(pkt);

        // VLAN intelligence
        let vlan_added = self.vlan_intel.ingest(pkt);
        for alert in self.vlan_intel.alerts.iter().skip(self.vlan_intel.alerts.len() - vlan_added) {
            self.alert_center.record_correlated_with_evidence(
                (alert.pkt_no, alert.related_packet.as_slice()),
                pkt.timestamp,
                "VLAN",
                alert.severity.to_string(),
                &alert.category,
                &alert.detail,
                alert.correlation_key.clone().unwrap_or_else(|| format!("{}>{}", pkt.src, pkt.dst)),
            );
        }

        // IOC matching
        let ioc_before = self.ioc_engine.hits.len();
        self.ioc_engine.check_packet(pkt);
        for hit in &self.ioc_engine.hits[ioc_before..] {
            self.operator_graph.on_ioc_hit(
                &hit.ioc.value,
                &hit.ioc.kind.to_string(),
                &hit.context,
                hit.pkt_no,
                hit.ts,
                &pkt.src,
            );
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
            self.operator_graph.on_rule_hit(
                &hit.rule_id,
                &hit.rule_name,
                &hit.message,
                hit.pkt_no,
                hit.ts,
            );
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
                self.operator_graph.on_credential(
                    Some(credential.kind),
                    &credential.proto,
                    true,
                    &pkt.src,
                    &pkt.dst,
                    pkt.timestamp,
                    credential.pkt_no,
                );
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
