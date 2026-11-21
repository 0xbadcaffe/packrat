use super::*;

impl SecurityEngine {
    // ─── C2 Beacon and Exfiltration Correlation ─────────────────────────────

    pub(super) fn check_beacon_and_exfiltration(&mut self, pkt: &Packet) {
        if ![&pkt.src, &pkt.dst].into_iter().all(|address| {
            match address.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(ip)) => {
                    !ip.is_multicast() && !ip.is_broadcast() && !ip.is_unspecified()
                }
                Ok(std::net::IpAddr::V6(ip)) => !ip.is_multicast() && !ip.is_unspecified(),
                Err(_) => false,
            }
        }) {
            return;
        }
        self.beacon_flows.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= 3600.0
        });
        self.exfil_flows.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= 3600.0
        });
        evict_oldest_exfil(&mut self.exfil_flows);
        self.check_periodic_traffic(pkt);
        let mut alerts = Vec::new();
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

    fn check_periodic_traffic(&mut self, pkt: &Packet) {
        let (Some(source_port), Some(destination_port)) = (pkt.src_port, pkt.dst_port) else {
            return;
        };
        let source = (pkt.src.as_str(), source_port);
        let destination = (pkt.dst.as_str(), destination_port);
        let (first, second, direction) = if source <= destination {
            (source, destination, 0)
        } else {
            (destination, source, 1)
        };
        let key = BehaviorFlowKey {
            first: (first.0.into(), first.1),
            second: (second.0.into(), second.1),
            protocol: pkt.protocol.clone(),
            vlan: (pkt.outer_vlan_id, pkt.vlan_id),
        };
        if !self.beacon_flows.contains_key(&key) {
            evict_oldest_beacon(&mut self.beacon_flows);
        }
        let state = self.beacon_flows.entry(key).or_default();
        state.last_seen = state.last_seen.max(pkt.timestamp);
        if state.alerted {
            return;
        }
        let samples = &mut state.directions[direction];
        if samples.last().is_some_and(|sample| pkt.timestamp <= sample.timestamp) {
            return;
        }
        samples.retain(|sample| pkt.timestamp - sample.timestamp <= 3600.0);
        if samples.len() == 32 {
            samples.remove(0);
        }
        samples.push(BeaconSample {
            timestamp: pkt.timestamp,
            size: pkt.length,
            packet_no: pkt.no,
        });
        if !beacon_pattern(samples) {
            return;
        }
        state.alerted = true;
        let related_packets = samples[..samples.len() - 1]
            .iter()
            .map(|sample| sample.packet_no)
            .collect();
        let count = samples.len();
        self.push_ids_finding(IdsFinding {
            alert: IdsAlert {
                pkt_no: pkt.no,
                signature: "Periodic fixed-size traffic",
                severity: Severity::Medium,
                detail: format!(
                    "{count} regularly timed, similar-size packets from {}:{} to {}:{}; timing alone does not establish command-and-control",
                    pkt.src, source_port, pkt.dst, destination_port,
                ),
            },
            related_packets,
            correlation_key: Some(format!(
                "{} [{:?},{:?}] [{}]:{}<>[{}]:{}",
                pkt.protocol, pkt.outer_vlan_id, pkt.vlan_id, first.0, first.1, second.0, second.1,
            )),
        });
    }

    // ─── DNS Abuse and Lateral Movement ─────────────────────────────────────

    pub(super) fn check_dns_abuse_and_lateral_movement(&mut self, pkt: &Packet) {
        let mut alerts = Vec::new();
        let is_dns = pkt.protocol.eq_ignore_ascii_case("DNS")
            || pkt.src_port == Some(53)
            || pkt.dst_port == Some(53);

        self.external_dns_pairs.retain(|_, last_seen| {
            pkt.timestamp < *last_seen || pkt.timestamp - *last_seen <= 3600.0
        });
        self.ntlm_fanout.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= 300.0
        });

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

        self.record_ntlm_fanout(pkt);

        for (signature, severity, detail) in alerts {
            self.push_ids(IdsAlert {
                pkt_no: pkt.no,
                signature,
                severity,
                detail,
            });
        }
    }

    fn record_ntlm_fanout(&mut self, pkt: &Packet) {
        if pkt.dst_port != Some(445)
            || !is_internal_address(&pkt.src)
            || !is_internal_address(&pkt.dst)
            || !crate::analysis::stream::tcp_segment_payload(pkt)
                .is_some_and(|(_, payload)| smb_wire::has_ntlm_authenticate(payload))
        {
            return;
        }
        let key = (pkt.src.clone(), service_scope(pkt));
        if self.ntlm_fanout.len() >= MAX_SCAN_STATES && !self.ntlm_fanout.contains_key(&key) {
            return;
        }
        let state = self.ntlm_fanout.entry(key).or_default();
        state.last_seen = if state.targets.is_empty() { pkt.timestamp } else { state.last_seen.max(pkt.timestamp) };
        if state.last_seen - pkt.timestamp > 300.0 {
            return;
        }
        state.targets.retain(|_, (seen, _)| state.last_seen - *seen <= 300.0);
        if state.targets.is_empty() {
            state.alerted = false;
        }
        if let Some(prior) = state.targets.get_mut(&pkt.dst) {
            if pkt.timestamp > prior.0 {
                *prior = (pkt.timestamp, pkt.no);
            }
        } else if state.targets.len() < 256 {
            state.targets.insert(pkt.dst.clone(), (pkt.timestamp, pkt.no));
        }
        let count = state.targets.len();
        if count < NTLM_TARGET_THRESHOLD || state.alerted {
            return;
        }
        state.alerted = true;
        let related_packets = state.targets.values().map(|&(_, frame)| frame)
            .filter(|&frame| frame != pkt.no).collect();
        self.push_ids_finding(IdsFinding {
            alert: IdsAlert {
                pkt_no: pkt.no,
                signature: "NTLM authentication fan-out",
                severity: Severity::Medium,
                detail: format!("{} sent SMB2 NTLM authentication to {count} internal hosts; outcomes unverified", pkt.src),
            },
            related_packets,
            correlation_key: Some(format!("{:?}:{}", service_scope(pkt), pkt.src)),
        });
    }
}
