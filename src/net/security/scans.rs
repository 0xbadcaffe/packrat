use super::*;
use super::findings::IdsEvidenceUpdate;

#[path = "scan_replies.rs"]
mod scan_replies;
#[path = "scan_echo.rs"]
mod scan_echo;

#[derive(Debug)]
pub(super) struct ScanProbe {
    timestamp: f64,
    packet_no: u64,
    destination: String,
    port: u16,
    tcp: Option<ScanTcpProbe>,
    vertical_opening: Option<u64>,
    horizontal_opening: Option<u64>,
}

#[derive(Debug, Default)]
struct ScanTcpProbe {
    source_port: u16,
    sequence: u32,
    payload_length: u32,
    syn_ack: Option<ScanSynAck>,
    reset_ack: Option<u64>,
    final_ack: Option<u64>,
}

#[derive(Debug)]
struct ScanSynAck {
    order: (f64, u64),
    sequence: u32,
    payload_length: u32,
    client_next_sequence: u32,
}

enum ProbeChange { Distinct, Replaced, Ignored }

impl ScanTcpProbe {
    fn awaits_final_ack(&self) -> bool {
        self.syn_ack.is_some() && self.reset_ack.is_none() && self.final_ack.is_none()
    }

    fn matches_syn(&self, other: &Self) -> bool {
        self.source_port == other.source_port && self.sequence == other.sequence
    }
}

impl ScanProbe {
    fn awaits_final_ack(&self) -> bool {
        self.tcp.as_ref().is_some_and(ScanTcpProbe::awaits_final_ack)
    }

    fn linked_to_alert(&self) -> bool {
        self.tcp.is_some() && (self.vertical_opening.is_some() || self.horizontal_opening.is_some())
    }

    fn reply_evidence(&self, frame: u64) -> impl Iterator<Item = IdsEvidenceUpdate> {
        [("Vertical port scan", self.vertical_opening), ("Horizontal host scan", self.horizontal_opening)]
            .into_iter().filter_map(move |(signature, opening)| Some(IdsEvidenceUpdate {
                signature, opening_frame: opening?, probe_frame: self.packet_no, evidence_frame: frame,
            }))
    }
}

impl SecurityEngine {
    // ─── Scan and Flood Correlation ─────────────────────────────────────────

    pub(super) fn check_scan_activity(&mut self, pkt: &Packet, archive_rules: Option<&[String]>) {
        if !pkt.timestamp.is_finite() {
            return;
        }
        let retain = archive_rules.is_some();
        let mut has_pending_final_ack = false;
        self.scan_sources.retain(|_, state| {
            let active = pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= SCAN_WINDOW_SECS;
            has_pending_final_ack |= active && state.pending_final_acks != 0;
            active
        });
        self.syn_flood_targets.retain(|_, state| {
            pkt.timestamp < state.last_seen
                || pkt.timestamp - state.last_seen <= SYN_RETRY_HISTORY_SECS
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
                        payload_length: segment.payload.len() as u32,
                        source_port: source.port(),
                        destination_port: destination.port(),
                        complete: segment.complete,
                    })
                }
                _ => None,
            },
        };
        let ipv4 = if tcp.is_none() && ipv6.is_none() {
            ipv4_discovery_probe(&pkt.bytes)
        } else {
            None
        };
        let mut alerts = Vec::new();

        if let Some(signal) = tcp.filter(|signal| signal.complete) {
            let TcpSignal { flags, sequence, source_port, destination_port, .. } = signal;
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
                let probe = ScanTcpProbe { source_port, sequence, payload_length: signal.payload_length, ..Default::default() };
                self.record_scan_probe(pkt, destination_port, "TCP", Some(probe), retain);
                self.record_syn_arrival(pkt, destination_port, source_port, sequence, retain);
                if destination_port == 22 && control == SYN {
                    self.record_service_observation(
                        pkt, "SSH", false, destination_port, (source_port, sequence), Vec::new(),
                        archive_rules,
                    );
                }
            } else if control == (SYN | ACK) || control == (RST | ACK) {
                if self.record_scan_reply(pkt, signal, control == (RST | ACK)) && retain {
                    self.scan_packet_evidence.remember(pkt);
                }
            } else if control & !PSH == ACK && has_pending_final_ack {
                if self.record_scan_final_ack(pkt, signal) && retain {
                    self.scan_packet_evidence.remember(pkt);
                }
            }
            self.record_admin_tcp(pkt, signal, archive_rules);
        } else if let Some(Ipv6Probe::EmptyUdp(port)) = ipv6 {
            self.record_scan_probe(pkt, port, "UDP", None, retain);
        } else if let Some(Ipv4DiscoveryProbe::EmptyUdp(port)) = ipv4 {
            self.record_scan_probe(pkt, port, "UDP", None, retain);
        }

        let echo_protocol = if matches!(ipv6, Some(Ipv6Probe::EchoRequest)) {
            Some("ICMPv6")
        } else if matches!(ipv4, Some(Ipv4DiscoveryProbe::EchoRequest)) {
            Some("ICMP")
        } else {
            None
        };
        if let Some(protocol) = echo_protocol {
            let retain_echo = archive_rules.is_some_and(|rules| rules.iter().any(|rule| rule == "icmp.address_sweep"));
            self.record_echo_request(pkt, protocol, retain_echo);
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

    fn record_scan_probe(&mut self, pkt: &Packet, port: u16, transport: &'static str, tcp: Option<ScanTcpProbe>, retain: bool) {
        let key = scan_key(pkt, transport);
        let state = self.scan_state(key.clone());
        match state.push_probe(pkt, port, tcp) {
            ProbeChange::Ignored => return,
            ProbeChange::Replaced => {
                if retain { self.scan_packet_evidence.remember(pkt); }
                return;
            }
            ProbeChange::Distinct => {}
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
        if vertical.is_some() || horizontal.is_some() {
            for probe in &mut state.probes {
                if vertical.is_some() && probe.destination == pkt.dst { probe.vertical_opening = Some(pkt.no); }
                if horizontal.is_some() && probe.port == port { probe.horizontal_opening = Some(pkt.no); }
            }
        }
        for finding in vertical.into_iter().chain(horizontal) {
            if retain {
                self.findings.retained_evidence.extend(finding.related_packets.iter().filter_map(|&frame| {
                    self.scan_packet_evidence.cited_packet(pkt, frame).cloned()
                }));
            }
            self.push_ids_finding(finding);
        }
        if retain { self.scan_packet_evidence.remember(pkt); }
    }

    fn record_syn_arrival(
        &mut self,
        pkt: &Packet,
        port: u16,
        source_port: u16,
        sequence: u32,
        retain: bool,
    ) {
        let scope = service_scope(pkt);
        let key = SynTargetKey {
            address: pkt.dst.clone(),
            port,
            scope,
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
        let mut active = 0;
        let mut repeat = false;
        state.attempts.retain(|attempt| {
            let age = state.last_seen - attempt.timestamp;
            if age > SYN_RETRY_HISTORY_SECS {
                return false;
            }
            active += usize::from(age <= SYN_FLOOD_WINDOW_SECS);
            repeat |= attempt.source == pkt.src
                && attempt.source_port == source_port && attempt.sequence == sequence;
            true
        });
        if active < SYN_FLOOD_THRESHOLD.div_ceil(2) {
            state.alerted = false;
        }
        if repeat {
            return;
        }
        if state.attempts.len() == MAX_SYN_HISTORY_PER_TARGET {
            let oldest = state.attempts.iter().enumerate()
                .min_by(|(_, a), (_, b)| a.timestamp.total_cmp(&b.timestamp).then(a.packet_no.cmp(&b.packet_no)))
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
        if active + 1 >= SYN_FLOOD_THRESHOLD && !state.alerted {
            state.alerted = true;
            let related_packets: Vec<_> = state.attempts.iter()
                .filter(|attempt| state.last_seen - attempt.timestamp <= SYN_FLOOD_WINDOW_SECS)
                .map(|attempt| attempt.packet_no)
                .filter(|&number| number != pkt.no).collect();
            if retain {
                self.findings.retained_evidence.extend(related_packets.iter().filter_map(|&frame| {
                    self.syn_arrival_evidence.cited_packet(pkt, frame).cloned()
                }));
            }
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: "SYN arrival spike",
                    severity: Severity::High,
                    detail: format!(
                        "{}:{} received {SYN_FLOOD_THRESHOLD} distinct TCP SYN attempts within one second after excluding retained retries; service impact is unverified",
                        pkt.dst, port,
                    ),
                },
                related_packets,
                correlation_key: Some(format!("{scope:?}:[{}]:{port}:burst:{}", pkt.dst, pkt.no)),
            });
        }
        if retain { self.syn_arrival_evidence.remember(pkt); }
    }
}

impl SourceScanState {
    fn push_probe(&mut self, pkt: &Packet, port: u16, tcp: Option<ScanTcpProbe>) -> ProbeChange {
        self.last_seen = if self.probes.is_empty() {
            pkt.timestamp
        } else {
            self.last_seen.max(pkt.timestamp)
        };
        if self.last_seen - pkt.timestamp > SCAN_WINDOW_SECS {
            return ProbeChange::Ignored;
        }
        let previous_len = self.probes.len();
        self.linked_probes.retain(|probe| {
            let keep = self.last_seen - probe.timestamp <= SCAN_WINDOW_SECS;
            self.pending_final_acks -= usize::from(!keep && probe.awaits_final_ack());
            keep
        });
        self.probes.retain(|probe| {
            let keep = self.last_seen - probe.timestamp <= SCAN_WINDOW_SECS;
            if !keep {
                self.pending_final_acks -= usize::from(probe.awaits_final_ack());
            }
            keep
        });
        if self.probes.len() < previous_len {
            // Rearm after most of the burst expires, not on every threshold crossing.
            let minimum = SCAN_UNIQUE_THRESHOLD.div_ceil(2);
            prune_scan_latches(self, minimum);
            if self.probes.len() < minimum {
                self.icmp_alerted = false;
            }
        }
        if let Some(attempt) = &tcp
            && self.linked_probes.iter().any(|prior| prior.destination == pkt.dst && prior.port == port
                && prior.tcp.as_ref().is_some_and(|old| old.matches_syn(attempt)))
        {
            return ProbeChange::Ignored;
        }
        if let Some(index) = self.probes.iter().position(|prior| {
            prior.destination == pkt.dst && prior.port == port
        }) {
            let probe = &mut self.probes[index];
            // An identical SYN retry is not a new attempt or a new evidence window.
            if probe.tcp.as_ref().zip(tcp.as_ref()).is_some_and(|(old, new)| old.matches_syn(new)) {
                return ProbeChange::Ignored;
            }
            if (probe.timestamp, probe.packet_no) < (pkt.timestamp, pkt.no) {
                let old = std::mem::replace(probe, ScanProbe::new(pkt, port, tcp));
                self.retain_linked_probe(old);
                return ProbeChange::Replaced;
            }
            return ProbeChange::Ignored;
        }
        if self.probes.len() == MAX_SCAN_PROBES_PER_SOURCE {
            let oldest = self.probes.iter().enumerate()
                .min_by(|(_, a), (_, b)| a.timestamp.total_cmp(&b.timestamp))
                .map(|(index, _)| index).unwrap_or(0);
            let removed = self.probes.remove(oldest);
            self.retain_linked_probe(removed);
            prune_scan_latches(self, 1);
        }
        self.probes.push(ScanProbe::new(pkt, port, tcp));
        ProbeChange::Distinct
    }
}

impl ScanProbe {
    fn new(pkt: &Packet, port: u16, tcp: Option<ScanTcpProbe>) -> Self {
        Self {
            timestamp: pkt.timestamp,
            packet_no: pkt.no,
            destination: pkt.dst.clone(),
            port,
            tcp,
            vertical_opening: None,
            horizontal_opening: None,
        }
    }
}

fn scan_key(pkt: &Packet, transport: &'static str) -> ScanSourceKey {
    ScanSourceKey {
        address: pkt.src.clone(),
        transport,
        scope: service_scope(pkt),
    }
}

fn prune_scan_latches(state: &mut SourceScanState, minimum: usize) {
    state.vertical_alerted.retain(|host| {
        state.probes.iter().filter(|probe| &probe.destination == host).take(minimum).count() == minimum
    });
    state.horizontal_alerted.retain(|port| {
        state.probes.iter().filter(|probe| &probe.port == port).take(minimum).count() == minimum
    });
}

fn scan_finding<'a>(
    pkt: &Packet,
    key: &ScanSourceKey,
    signature: &'static str,
    target: &str,
    mut detail: String,
    probes: impl Iterator<Item = &'a ScanProbe>,
) -> IdsFinding {
    use std::fmt::Write as _;
    let (mut syn_acks, mut resets, mut final_acks) = (0, 0, 0);
    let (mut earliest, mut latest) = (pkt.timestamp, pkt.timestamp);
    let mut related_packets = Vec::new();
    for probe in probes {
        earliest = earliest.min(probe.timestamp);
        latest = latest.max(probe.timestamp);
        if probe.packet_no != pkt.no {
            related_packets.push(probe.packet_no);
        }
        if let Some(tcp) = &probe.tcp {
            syn_acks += usize::from(tcp.syn_ack.is_some());
            resets += usize::from(tcp.reset_ack.is_some());
            final_acks += usize::from(tcp.final_ack.is_some());
            related_packets.extend(tcp.syn_ack.as_ref().map(|reply| reply.order.1));
            related_packets.extend(tcp.reset_ack);
            related_packets.extend(tcp.final_ack);
        }
    }
    let _ = write!(detail, " over {:.3}s within a {SCAN_WINDOW_SECS:.0}s observation window", latest - earliest);
    if key.transport == "TCP" {
        let _ = write!(detail, "; matched replies at alert time: SYN-ACK={syn_acks}, RST-ACK={resets}; matched final ACKs={final_acks}; missing ACKs do not prove failure; intent unverified");
    }
    IdsFinding {
        alert: IdsAlert { pkt_no: pkt.no, signature, severity: Severity::High, detail },
        related_packets,
        // The detector's latch groups sustained observations within a burst.
        correlation_key: Some(format!("{}:{:?}:{}:{target}:burst:{}", key.transport, key.scope, key.address, pkt.no)),
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/security_scan_state_tests.rs"]
mod tests;
