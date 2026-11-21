use super::*;

impl SecurityEngine {
    // ─── Scan and Flood Correlation ─────────────────────────────────────────

    pub(super) fn check_scan_activity(&mut self, pkt: &Packet) {
        self.scan_sources.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= SCAN_WINDOW_SECS
        });
        self.syn_flood_targets.retain(|_, state| {
            pkt.timestamp < state.last_seen
                || pkt.timestamp - state.last_seen <= SYN_FLOOD_WINDOW_SECS
        });
        let tcp_flags = match parse_ipv4_tcp_frame(&pkt.bytes) {
            Some(TcpFrame::Segment(segment)) => Some((segment.flags, segment.sequence)),
            _ => None,
        };
        let mut alerts = Vec::new();

        if let Some((flags, sequence)) = tcp_flags {
            const FIN: u8 = 0x01;
            const SYN: u8 = 0x02;
            const RST: u8 = 0x04;
            const PSH: u8 = 0x08;
            const ACK: u8 = 0x10;
            const URG: u8 = 0x20;
            let control = flags & (FIN | SYN | RST | PSH | ACK | URG);
            let stealth_kind = if control == 0 {
                Some("NULL")
            } else if control == FIN {
                Some("FIN")
            } else if control & (FIN | PSH | URG) == (FIN | PSH | URG)
                && control & (SYN | ACK | RST) == 0
            {
                Some("Xmas")
            } else {
                None
            };
            if let Some(kind) = stealth_kind {
                alerts.push((
                    "TCP stealth scan probe",
                    Severity::Medium,
                    format!(
                        "{kind} probe from {} to {}:{}",
                        pkt.src,
                        pkt.dst,
                        pkt.dst_port.unwrap_or(0)
                    ),
                ));
            }

            if flags & (SYN | ACK | FIN | RST) == SYN && let Some(port) = pkt.dst_port {
                self.record_scan_probe(pkt, port, "TCP");
                if let Some(source_port) = pkt.src_port {
                    self.record_syn_arrival(pkt, port, source_port, sequence);
                }
            }
        } else if is_empty_ipv4_udp_probe(&pkt.bytes) {
            if let Some(port) = pkt.dst_port {
                self.record_scan_probe(pkt, port, "UDP");
            }
        }

        if pkt.protocol.eq_ignore_ascii_case("ICMP")
            && pkt.info.to_ascii_lowercase().contains("echo request")
        {
            let state = self.scan_state(scan_key(pkt, "ICMP"));
            state.last_seen = pkt.timestamp;
            state.icmp_targets.retain(|(timestamp, _)| {
                pkt.timestamp < *timestamp || pkt.timestamp - *timestamp <= SCAN_WINDOW_SECS
            });
            if state.icmp_targets.is_empty() {
                state.icmp_alerted = false;
            }
            if state.icmp_targets.len() == MAX_SCAN_PROBES_PER_SOURCE {
                state.icmp_targets.remove(0);
            }
            state.icmp_targets.push((pkt.timestamp, pkt.dst.clone()));
            let unique_targets = state
                .icmp_targets
                .iter()
                .map(|(_, destination)| destination.as_str())
                .collect::<HashSet<_>>()
                .len();
            if unique_targets >= SCAN_UNIQUE_THRESHOLD && !state.icmp_alerted {
                state.icmp_alerted = true;
                alerts.push((
                    "ICMP address sweep",
                    Severity::Medium,
                    format!(
                        "{} probed {unique_targets} hosts with ICMP echo requests",
                        pkt.src
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

    fn scan_state(&mut self, key: ScanSourceKey) -> &mut SourceScanState {
        if !self.scan_sources.contains_key(&key) {
            evict_oldest_scan_source(&mut self.scan_sources);
        }
        self.scan_sources.entry(key).or_default()
    }

    fn record_scan_probe(&mut self, pkt: &Packet, port: u16, transport: &'static str) {
        let key = scan_key(pkt, transport);
        let state = self.scan_state(key.clone());
        state.last_seen = if state.probes.is_empty() {
            pkt.timestamp
        } else {
            state.last_seen.max(pkt.timestamp)
        };
        if state.last_seen - pkt.timestamp > SCAN_WINDOW_SECS {
            return;
        }
        let previous_len = state.probes.len();
        state.probes.retain(|probe| {
            state.last_seen - probe.timestamp <= SCAN_WINDOW_SECS
        });
        if let Some(index) = state
            .probes
            .iter()
            .position(|prior| prior.destination == pkt.dst && prior.port == port)
        {
            prune_scan_latches(state, previous_len);
            // Don't count retransmissions or replays as another unique destination.
            if state.probes[index].timestamp <= pkt.timestamp {
                state.probes[index].timestamp = pkt.timestamp;
                state.probes[index].packet_no = pkt.no;
            }
            return;
        }
        if state.probes.len() == MAX_SCAN_PROBES_PER_SOURCE {
            let oldest = state.probes.iter().enumerate()
                .min_by(|(_, a), (_, b)| a.timestamp.total_cmp(&b.timestamp))
                .map(|(index, _)| index).unwrap_or(0);
            state.probes.remove(oldest);
        }
        prune_scan_latches(state, previous_len);
        state.probes.push(ScanProbe {
            timestamp: pkt.timestamp,
            packet_no: pkt.no,
            destination: pkt.dst.clone(),
            port,
        });

        let unique_ports = state
            .probes
            .iter()
            .filter(|probe| probe.destination == pkt.dst)
            .count();
        let vertical = (unique_ports >= SCAN_UNIQUE_THRESHOLD
            && state.vertical_alerted.insert(pkt.dst.clone()))
            .then(|| scan_finding(
                pkt, &key, "Vertical port scan", &format!("host:{}", pkt.dst),
                format!("{} probed {unique_ports} {transport} ports on {}", pkt.src, pkt.dst),
                state.probes.iter().filter(|probe| probe.destination == pkt.dst),
            ));

        let unique_targets = state
            .probes
            .iter()
            .filter(|probe| probe.port == port)
            .count();
        let horizontal = (unique_targets >= SCAN_UNIQUE_THRESHOLD
            && state.horizontal_alerted.insert(port))
            .then(|| scan_finding(
                pkt, &key, "Horizontal host scan", &format!("port:{port}"),
                format!("{} probed {transport} port {port} on {unique_targets} hosts", pkt.src),
                state.probes.iter().filter(|probe| probe.port == port),
            ));
        for finding in vertical.into_iter().chain(horizontal) {
            self.push_ids_finding(finding);
        }
    }

    fn record_syn_arrival(
        &mut self,
        pkt: &Packet,
        port: u16,
        source_port: u16,
        sequence: u32,
    ) {
        let key = SynTargetKey {
            address: pkt.dst.clone(),
            port,
            vlan: (pkt.outer_vlan_id, pkt.vlan_id),
        };
        if !self.syn_flood_targets.contains_key(&key) {
            evict_oldest_syn_target(&mut self.syn_flood_targets);
        }
        let state = self.syn_flood_targets.entry(key).or_default();
        state.last_seen = if state.attempts.is_empty() {
            pkt.timestamp
        } else {
            state.last_seen.max(pkt.timestamp)
        };
        if state.last_seen - pkt.timestamp > SYN_FLOOD_WINDOW_SECS {
            return;
        }
        // Keep distinct attempts within one second of the latest observed packet.
        state.attempts.retain(|attempt| state.last_seen - attempt.timestamp <= SYN_FLOOD_WINDOW_SECS);
        if state.attempts.is_empty() {
            state.alerted = false;
        }
        if state.attempts.iter().any(|attempt| {
            attempt.source == pkt.src && attempt.source_port == source_port && attempt.sequence == sequence
        }) {
            return;
        }
        if state.attempts.len() == SYN_FLOOD_THRESHOLD {
            let oldest = state.attempts.iter().enumerate()
                .min_by(|(_, a), (_, b)| a.timestamp.total_cmp(&b.timestamp))
                .map(|(index, _)| index).unwrap_or(0);
            state.attempts.remove(oldest);
        }
        state.attempts.push(SynAttempt {
            source: pkt.src.clone(),
            source_port,
            sequence,
            timestamp: pkt.timestamp,
            packet_no: pkt.no,
        });
        if state.attempts.len() == SYN_FLOOD_THRESHOLD && !state.alerted {
            state.alerted = true;
            let related_packets = state.attempts.iter().map(|attempt| attempt.packet_no)
                .filter(|&number| number != pkt.no).collect();
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: "SYN arrival spike",
                    severity: Severity::High,
                    detail: format!(
                        "{}:{} received {SYN_FLOOD_THRESHOLD} distinct TCP SYN attempts within one second; service impact is unverified",
                        pkt.dst, port,
                    ),
                },
                related_packets,
                correlation_key: Some(format!("{:?}:[{}]:{port}", (pkt.outer_vlan_id, pkt.vlan_id), pkt.dst)),
            });
        }
    }
}

fn scan_key(pkt: &Packet, transport: &'static str) -> ScanSourceKey {
    ScanSourceKey {
        address: pkt.src.clone(),
        transport,
        vlan: (pkt.outer_vlan_id, pkt.vlan_id),
    }
}

fn prune_scan_latches(state: &mut SourceScanState, previous_len: usize) {
    if state.probes.len() < previous_len {
        state.vertical_alerted.retain(|host| state.probes.iter().any(|probe| &probe.destination == host));
        state.horizontal_alerted.retain(|port| state.probes.iter().any(|probe| &probe.port == port));
    }
}

fn scan_finding<'a>(
    pkt: &Packet,
    key: &ScanSourceKey,
    signature: &'static str,
    target: &str,
    detail: String,
    probes: impl Iterator<Item = &'a ScanProbe>,
) -> IdsFinding {
    IdsFinding {
        alert: IdsAlert { pkt_no: pkt.no, signature, severity: Severity::High, detail },
        related_packets: probes.map(|probe| probe.packet_no).filter(|&no| no != pkt.no).collect(),
        correlation_key: Some(format!("{}:{:?}:{}:{target}", key.transport, key.vlan, key.address)),
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/security_scan_state_tests.rs"]
mod tests;
