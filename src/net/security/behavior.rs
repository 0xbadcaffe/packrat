use super::*;

impl SecurityEngine {
    // ─── C2 Beacon and Exfiltration Correlation ─────────────────────────────

    pub(super) fn check_beacon_and_exfiltration(&mut self, pkt: &Packet) {
        self.beacon_flows.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= 3600.0
        });
        self.exfil_flows.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= 3600.0
        });
        evict_oldest_beacon(&mut self.beacon_flows);
        evict_oldest_exfil(&mut self.exfil_flows);

        let mut alerts = Vec::new();
        if pkt.src_port.is_some() && pkt.dst_port.is_some() {
            let key = BehaviorFlowKey {
                source: pkt.src.clone(),
                destination: pkt.dst.clone(),
                source_port: pkt.src_port.unwrap_or(0),
                destination_port: pkt.dst_port.unwrap_or(0),
                protocol: pkt.protocol.clone(),
            };
            let state = self.beacon_flows.entry(key).or_default();
            state.last_seen = pkt.timestamp;
            state.timestamps.push(pkt.timestamp);
            state.sizes.push(pkt.length);
            if state.timestamps.len() > 32 {
                state.timestamps.remove(0);
                state.sizes.remove(0);
            }
            if !state.alerted && beacon_pattern(state) {
                state.alerted = true;
                alerts.push((
                    "Periodic command-and-control beacon",
                    Severity::High,
                    format!(
                        "Regular fixed-size communication from {} to {}:{}",
                        pkt.src,
                        pkt.dst,
                        pkt.dst_port.unwrap_or(0)
                    ),
                ));
            }
        }

        let source_internal = is_internal_address(&pkt.src);
        let destination_internal = is_internal_address(&pkt.dst);
        if source_internal != destination_internal {
            let outbound = source_internal;
            let (internal, external) = if outbound {
                (pkt.src.clone(), pkt.dst.clone())
            } else {
                (pkt.dst.clone(), pkt.src.clone())
            };
            let key = ExfilKey {
                internal,
                external,
                destination_port: if outbound { pkt.dst_port } else { pkt.src_port }.unwrap_or(0),
                protocol: pkt.protocol.clone(),
            };
            let state = self.exfil_flows.entry(key).or_default();
            state.last_seen = pkt.timestamp;
            if outbound {
                state.outbound_bytes = state.outbound_bytes.saturating_add(u64::from(pkt.length));
                if pkt.bytes.len() >= 64 && shannon_entropy(&pkt.bytes) >= 7.2 {
                    state.high_entropy_bytes = state
                        .high_entropy_bytes
                        .saturating_add(u64::from(pkt.length));
                }
            } else {
                state.inbound_bytes = state.inbound_bytes.saturating_add(u64::from(pkt.length));
            }

            let outbound_ratio = state.outbound_bytes as f64 / state.inbound_bytes.max(1) as f64;
            if outbound
                && !state.volume_alerted
                && state.outbound_bytes >= EXFIL_VOLUME_THRESHOLD
                && outbound_ratio >= 10.0
            {
                state.volume_alerted = true;
                alerts.push((
                    "Large asymmetric outbound transfer",
                    Severity::High,
                    format!(
                        "{} sent {} bytes to {} with {:.1}:1 outbound ratio",
                        pkt.src, state.outbound_bytes, pkt.dst, outbound_ratio
                    ),
                ));
            }
            if outbound
                && !state.entropy_alerted
                && state.high_entropy_bytes >= EXFIL_ENTROPY_THRESHOLD
                && state.high_entropy_bytes * 100 / state.outbound_bytes.max(1) >= 80
            {
                state.entropy_alerted = true;
                alerts.push((
                    "High-entropy outbound transfer",
                    Severity::High,
                    format!(
                        "{} sent {} high-entropy bytes toward {}",
                        pkt.src, state.high_entropy_bytes, pkt.dst
                    ),
                ));
            }
        }

        for (signature, severity, detail) in alerts {
            self.push_ids(IdsAlert {
                pkt_no: pkt.no,
                signature,
                severity,
                detail,
            });
        }
    }

    // ─── DNS Abuse and Lateral Movement ─────────────────────────────────────

    pub(super) fn check_dns_abuse_and_lateral_movement(&mut self, pkt: &Packet) {
        let mut alerts = Vec::new();
        let is_dns = pkt.protocol.eq_ignore_ascii_case("DNS")
            || pkt.src_port == Some(53)
            || pkt.dst_port == Some(53);

        self.nxdomain_clients.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= 30.0
        });
        self.external_dns_pairs.retain(|_, last_seen| {
            pkt.timestamp < *last_seen || pkt.timestamp - *last_seen <= 3600.0
        });
        self.admin_fanout.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= 60.0
        });
        self.ntlm_fanout.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= 300.0
        });

        if is_dns && Self::contains_str_ci(pkt.info.as_bytes(), b"nxdomain") {
            let client = if pkt.src_port == Some(53) {
                pkt.dst.clone()
            } else {
                pkt.src.clone()
            };
            if self.nxdomain_clients.len() < MAX_SCAN_STATES
                || self.nxdomain_clients.contains_key(&client)
            {
                let state = self.nxdomain_clients.entry(client.clone()).or_default();
                state.last_seen = pkt.timestamp;
                state.timestamps.retain(|timestamp| {
                    pkt.timestamp < *timestamp || pkt.timestamp - *timestamp <= 30.0
                });
                if state.timestamps.is_empty() {
                    state.alerted = false;
                }
                state.timestamps.push(pkt.timestamp);
                if state.timestamps.len() >= DNS_NXDOMAIN_THRESHOLD && !state.alerted {
                    state.alerted = true;
                    alerts.push((
                        "DNS NXDOMAIN burst",
                        Severity::Medium,
                        format!(
                            "{client} received {} NXDOMAIN responses within 30 seconds",
                            state.timestamps.len()
                        ),
                    ));
                }
            }
        }

        if is_dns && Self::contains_str_ci(pkt.info.as_bytes(), b"txt") && pkt.length > 512 {
            alerts.push((
                "Oversized DNS TXT traffic",
                Severity::Medium,
                format!(
                    "{}-byte DNS TXT traffic between {} and {}",
                    pkt.length, pkt.src, pkt.dst
                ),
            ));
        }

        if pkt.dst_port == Some(53)
            && is_internal_address(&pkt.src)
            && !is_internal_address(&pkt.dst)
        {
            let key = (pkt.src.clone(), pkt.dst.clone());
            if !self.external_dns_pairs.contains_key(&key) {
                alerts.push((
                    "Direct external DNS resolver use",
                    Severity::Low,
                    format!(
                        "{} sent DNS directly to public resolver {}",
                        pkt.src, pkt.dst
                    ),
                ));
            }
            if self.external_dns_pairs.len() < MAX_SCAN_STATES
                || self.external_dns_pairs.contains_key(&key)
            {
                self.external_dns_pairs.insert(key, pkt.timestamp);
            }
        }

        let destination_port = pkt.dst_port.unwrap_or(0);
        if is_internal_address(&pkt.src)
            && is_internal_address(&pkt.dst)
            && matches!(destination_port, 22 | 135 | 139 | 445 | 3389 | 5985 | 5986)
        {
            let key = (pkt.src.clone(), destination_port);
            if self.admin_fanout.len() < MAX_SCAN_STATES || self.admin_fanout.contains_key(&key) {
                let state = self.admin_fanout.entry(key).or_default();
                state.last_seen = pkt.timestamp;
                record_timed_target(state, pkt.timestamp, &pkt.dst, 60.0);
                let unique_targets = unique_timed_targets(state);
                if unique_targets >= LATERAL_TARGET_THRESHOLD && !state.alerted {
                    state.alerted = true;
                    alerts.push((
                        "Administrative service fan-out",
                        Severity::High,
                        format!("{} contacted {unique_targets} internal hosts on port {destination_port}", pkt.src),
                    ));
                }
            }
        }

        if Self::contains_str_ci(&pkt.bytes, b"NTLMSSP") && is_internal_address(&pkt.src) {
            let source = pkt.src.clone();
            if self.ntlm_fanout.len() < MAX_SCAN_STATES || self.ntlm_fanout.contains_key(&source) {
                let state = self.ntlm_fanout.entry(source.clone()).or_default();
                state.last_seen = pkt.timestamp;
                record_timed_target(state, pkt.timestamp, &pkt.dst, 300.0);
                let unique_targets = unique_timed_targets(state);
                if unique_targets >= NTLM_TARGET_THRESHOLD && !state.alerted {
                    state.alerted = true;
                    alerts.push((
                        "NTLM authentication fan-out",
                        Severity::High,
                        format!("{source} sent NTLM authentication to {unique_targets} hosts"),
                    ));
                }
            }
        }

        for (signature, severity, detail) in alerts {
            self.push_ids(IdsAlert {
                pkt_no: pkt.no,
                signature,
                severity,
                detail,
            });
        }
    }
}
