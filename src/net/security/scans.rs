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
        let ipv6 = ipv6_probe(&pkt.bytes);
        let tcp = match ipv6 {
            Some(Ipv6Probe::Tcp(signal)) => Some(signal),
            _ => match parse_ipv4_tcp_frame(&pkt.bytes) {
                Some(TcpFrame::Segment(segment)) => {
                    let (source, destination) = if segment.from_a {
                        (segment.key.endpoint_a, segment.key.endpoint_b)
                    } else {
                        (segment.key.endpoint_b, segment.key.endpoint_a)
                    };
                    Some(TcpSignal {
                        flags: segment.flags,
                        sequence: segment.sequence,
                        acknowledgement: segment.acknowledgement,
                        source_port: source.1,
                        destination_port: destination.1,
                        complete: segment.complete,
                    })
                }
                _ => None,
            },
        };
        let mut alerts = Vec::new();

        if let Some(signal) = tcp {
            let TcpSignal { flags, sequence, source_port, destination_port, complete, .. } = signal;
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
                        destination_port
                    ),
                ));
            }

            if flags & (SYN | ACK | FIN | RST) == SYN {
                self.record_scan_probe(pkt, destination_port, "TCP");
                self.record_syn_arrival(pkt, destination_port, source_port, sequence);
                if destination_port == 22 && complete && control == SYN {
                    self.record_service_observation(
                        pkt, "SSH", false, destination_port, (source_port, sequence),
                    );
                }
            }
            self.record_admin_tcp(pkt, signal);
        } else if let Some(Ipv6Probe::EmptyUdp(port)) = ipv6 {
            self.record_scan_probe(pkt, port, "UDP");
        } else if is_empty_ipv4_udp_probe(&pkt.bytes) {
            if let Some(port) = pkt.dst_port {
                self.record_scan_probe(pkt, port, "UDP");
            }
        }

        let echo_protocol = if matches!(ipv6, Some(Ipv6Probe::EchoRequest)) {
            Some("ICMPv6")
        } else if pkt.protocol.eq_ignore_ascii_case("ICMP")
            && pkt.info.to_ascii_lowercase().contains("echo request")
        {
            Some("ICMP")
        } else {
            None
        };
        if let Some(protocol) = echo_protocol {
            self.record_echo_request(pkt, protocol);
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

    fn record_echo_request(&mut self, pkt: &Packet, protocol: &'static str) {
        let key = scan_key(pkt, protocol);
        let state = self.scan_state(key.clone());
        if !state.push_probe(pkt, 0) {
            return;
        }
        let count = state.probes.len();
        if count < SCAN_UNIQUE_THRESHOLD || state.icmp_alerted {
            return;
        }
        state.icmp_alerted = true;
        let mut finding = scan_finding(
            pkt,
            &key,
            "ICMP address sweep",
            "echo",
            format!("{} probed {count} hosts with {protocol} echo requests", pkt.src),
            state.probes.iter(),
        );
        finding.alert.severity = Severity::Medium;
        self.push_ids_finding(finding);
    }

    fn record_scan_probe(&mut self, pkt: &Packet, port: u16, transport: &'static str) {
        let key = scan_key(pkt, transport);
        let state = self.scan_state(key.clone());
        if !state.push_probe(pkt, port) {
            return;
        }

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

impl SourceScanState {
    fn push_probe(&mut self, pkt: &Packet, port: u16) -> bool {
        self.last_seen = if self.probes.is_empty() {
            pkt.timestamp
        } else {
            self.last_seen.max(pkt.timestamp)
        };
        if self.last_seen - pkt.timestamp > SCAN_WINDOW_SECS {
            return false;
        }
        let previous_len = self.probes.len();
        self.probes.retain(|probe| self.last_seen - probe.timestamp <= SCAN_WINDOW_SECS);
        if self.probes.is_empty() {
            self.icmp_alerted = false;
        }
        if let Some(index) = self.probes.iter().position(|prior| {
            prior.destination == pkt.dst && prior.port == port
        }) {
            prune_scan_latches(self, previous_len);
            if self.probes[index].timestamp <= pkt.timestamp {
                self.probes[index].timestamp = pkt.timestamp;
                self.probes[index].packet_no = pkt.no;
            }
            return false;
        }
        if self.probes.len() == MAX_SCAN_PROBES_PER_SOURCE {
            let oldest = self.probes.iter().enumerate()
                .min_by(|(_, a), (_, b)| a.timestamp.total_cmp(&b.timestamp))
                .map(|(index, _)| index).unwrap_or(0);
            self.probes.remove(oldest);
        }
        prune_scan_latches(self, previous_len);
        self.probes.push(ScanProbe {
            timestamp: pkt.timestamp,
            packet_no: pkt.no,
            destination: pkt.dst.clone(),
            port,
        });
        true
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
