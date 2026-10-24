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
        evict_oldest_scan_source(&mut self.scan_sources);
        evict_oldest_syn_target(&mut self.syn_flood_targets);

        let tcp_flags = match parse_ipv4_tcp_frame(&pkt.bytes) {
            Some(TcpFrame::Segment(segment)) => Some(segment.flags),
            _ => None,
        };
        let mut alerts = Vec::new();

        if let Some(flags) = tcp_flags {
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

            if flags & SYN != 0 && flags & ACK == 0 {
                let port = pkt.dst_port.unwrap_or(0);
                self.record_scan_probe(pkt, port, &mut alerts);
                self.record_syn_flood(pkt, port, &mut alerts);
            }
        } else if is_empty_ipv4_udp_probe(&pkt.bytes) {
            if let Some(port) = pkt.dst_port {
                self.record_scan_probe(pkt, port, &mut alerts);
            }
        }

        if pkt.protocol.eq_ignore_ascii_case("ICMP")
            && pkt.info.to_ascii_lowercase().contains("echo request")
        {
            let state = self.scan_sources.entry(pkt.src.clone()).or_default();
            state.last_seen = pkt.timestamp;
            state.icmp_targets.retain(|(timestamp, _)| {
                pkt.timestamp < *timestamp || pkt.timestamp - *timestamp <= SCAN_WINDOW_SECS
            });
            if state.icmp_targets.is_empty() {
                state.icmp_alerted = false;
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

    pub(super) fn record_scan_probe(
        &mut self,
        pkt: &Packet,
        port: u16,
        alerts: &mut Vec<(&'static str, Severity, String)>,
    ) {
        let state = self.scan_sources.entry(pkt.src.clone()).or_default();
        state.last_seen = pkt.timestamp;
        state.probes.retain(|probe| {
            pkt.timestamp < probe.timestamp || pkt.timestamp - probe.timestamp <= SCAN_WINDOW_SECS
        });
        if state.probes.is_empty() {
            state.vertical_alerted.clear();
            state.horizontal_alerted.clear();
        }
        state.probes.push(ScanProbe {
            timestamp: pkt.timestamp,
            destination: pkt.dst.clone(),
            port,
        });

        let unique_ports = state
            .probes
            .iter()
            .filter(|probe| probe.destination == pkt.dst)
            .map(|probe| probe.port)
            .collect::<HashSet<_>>()
            .len();
        if unique_ports >= SCAN_UNIQUE_THRESHOLD && state.vertical_alerted.insert(pkt.dst.clone()) {
            alerts.push((
                "Vertical port scan",
                Severity::High,
                format!("{} probed {unique_ports} ports on {}", pkt.src, pkt.dst),
            ));
        }

        let unique_targets = state
            .probes
            .iter()
            .filter(|probe| probe.port == port)
            .map(|probe| probe.destination.as_str())
            .collect::<HashSet<_>>()
            .len();
        if unique_targets >= SCAN_UNIQUE_THRESHOLD && state.horizontal_alerted.insert(port) {
            alerts.push((
                "Horizontal host scan",
                Severity::High,
                format!("{} probed port {port} on {unique_targets} hosts", pkt.src),
            ));
        }
    }

    pub(super) fn record_syn_flood(
        &mut self,
        pkt: &Packet,
        port: u16,
        alerts: &mut Vec<(&'static str, Severity, String)>,
    ) {
        let key = (pkt.dst.clone(), port);
        let state = self.syn_flood_targets.entry(key).or_default();
        state.last_seen = pkt.timestamp;
        state.timestamps.retain(|timestamp| {
            pkt.timestamp < *timestamp || pkt.timestamp - *timestamp <= SYN_FLOOD_WINDOW_SECS
        });
        if state.timestamps.is_empty() {
            state.alerted = false;
        }
        state.timestamps.push(pkt.timestamp);
        if state.timestamps.len() >= SYN_FLOOD_THRESHOLD && !state.alerted {
            state.alerted = true;
            alerts.push((
                "SYN flood",
                Severity::Critical,
                format!(
                    "{}:{} received {} SYN packets within one second",
                    pkt.dst,
                    port,
                    state.timestamps.len()
                ),
            ));
        }
    }
}
