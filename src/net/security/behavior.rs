use super::*;
use super::fragments::TcpPayloadObservation;
use super::scans::scan_scope;
use std::collections::VecDeque;

pub(super) const MAX_CANDIDATE_FRAME_COST: usize = 2 * 1024;
const MAX_TRANSFER_SAMPLE_FRAMES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum VolumeEvidence {
    OneWay,
    BothDirections,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct VolumeEpisode {
    opening_frame: u64,
    evidence: VolumeEvidence,
}

#[derive(Debug)]
pub(super) struct TransferSample {
    minute: i64,
    timestamp: f64,
    frame: u64,
    client_port: Option<u16>,
    evidence: Option<Box<Packet>>,
}

fn sample_transfer_frame(frames: &mut VecDeque<TransferSample>, minute: i64, packet: &Packet, client_port: Option<u16>, retain: bool) {
    let mut index = frames.partition_point(|sample| {
        sample.timestamp.total_cmp(&packet.timestamp).then(sample.frame.cmp(&packet.no)).is_lt()
    });
    if frames.len() == MAX_TRANSFER_SAMPLE_FRAMES {
        if index == 0 { return; }
        frames.pop_front();
        index -= 1;
    }
    frames.insert(index, TransferSample {
        minute,
        timestamp: packet.timestamp,
        frame: packet.no,
        client_port,
        evidence: (retain && crate::model::project::pinned_packet_cost(packet) <= MAX_CANDIDATE_FRAME_COST)
            .then(|| Box::new(packet.clone())),
    });
}

fn observed_transport_payload(packet: &Packet) -> Option<&[u8]> {
    if let Some((_, _, payload)) = crate::analysis::dns_transactions::udp_payload(packet) {
        return Some(payload);
    }
    match parse_ipv4_tcp_frame(&packet.bytes).or_else(|| parse_ipv6_tcp_frame(&packet.bytes)) {
        Some(TcpFrame::Segment(segment)) if segment.complete => Some(segment.payload),
        _ => None,
    }
}

fn transfer_transport(packet: &Packet) -> TransferTransport {
    if let Some(ports) = packet.src_port.zip(packet.dst_port) {
        if crate::analysis::stream::tcp_port_pair(packet) == Some(ports) {
            return TransferTransport::Tcp;
        }
        if crate::analysis::dns_transactions::udp_port_pair(packet) == Some(ports) {
            return TransferTransport::Udp;
        }
    }
    TransferTransport::Other(packet.protocol.clone())
}

impl ExfilState {
    fn paired_samples(&self) -> bool {
        self.inbound_frames.iter().any(|reverse| reverse.client_port.is_some()
            && self.outbound_frames.iter().any(|forward| forward.client_port == reverse.client_port))
    }

    fn observe(
        &mut self, packet: &Packet, outbound: bool, tcp: &TcpPayloadObservation,
        client_port: Option<u16>, retain_volume: bool, retain_entropy: bool,
    ) -> Option<bool> {
        if !packet.timestamp.is_finite() {
            return None;
        }
        if self.buckets.is_empty() || packet.timestamp > self.last_seen {
            self.last_seen = packet.timestamp;
        }
        let minute = (packet.timestamp / 60.0).floor() as i64;
        // The current minute and 59 preceding minutes bound memory independently of packet rate.
        let cutoff = ((self.last_seen / 60.0).floor() as i64).saturating_sub(59);
        if minute < cutoff {
            return None;
        }
        let mut expired = false;
        while self.buckets.front().is_some_and(|bucket| bucket.minute < cutoff) {
            let Some(bucket) = self.buckets.pop_front() else { break };
            self.outbound_bytes = self.outbound_bytes.saturating_sub(bucket.outbound);
            self.outbound_payload_bytes = self.outbound_payload_bytes.saturating_sub(bucket.outbound_payload);
            self.inbound_bytes = self.inbound_bytes.saturating_sub(bucket.inbound);
            self.high_entropy_bytes = self.high_entropy_bytes.saturating_sub(bucket.entropy);
            expired = true;
        }
        if expired {
            for frames in [&mut self.outbound_frames, &mut self.inbound_frames, &mut self.entropy_frames] {
                frames.retain(|sample| sample.minute >= cutoff);
            }
            if self.outbound_bytes < EXFIL_VOLUME_THRESHOLD / 2 {
                self.volume_episode = None;
            }
            self.entropy_alerted &= self.high_entropy_bytes >= EXFIL_ENTROPY_THRESHOLD / 2;
        }
        let index = if self.buckets.back().is_none_or(|bucket| bucket.minute < minute) {
            self.buckets.push_back(TransferBucket { minute, ..Default::default() });
            self.buckets.len() - 1
        } else if self.buckets.back().is_some_and(|bucket| bucket.minute == minute) {
            self.buckets.len() - 1
        } else {
            match self.buckets.make_contiguous().binary_search_by_key(&minute, |bucket| bucket.minute) {
                Ok(index) => index,
                Err(index) => {
                    self.buckets.insert(index, TransferBucket { minute, ..Default::default() });
                    index
                }
            }
        };
        let bucket = &mut self.buckets[index];
        let repeated = match tcp {
            TcpPayloadObservation::Partial { repeated_bytes, .. } if outbound => *repeated_bytes,
            _ => 0,
        };
        let length = packet.bytes.len().saturating_sub(repeated) as u64;
        let mut high_entropy_payload = false;
        if outbound {
            bucket.outbound = bucket.outbound.saturating_add(length);
            self.outbound_bytes = self.outbound_bytes.saturating_add(length);
            sample_transfer_frame(&mut self.outbound_frames, minute, packet, client_port, retain_volume);
            if !matches!(tcp, TcpPayloadObservation::Empty | TcpPayloadObservation::Repeat)
                && let Some(payload) = observed_transport_payload(packet)
            {
                let payload_bytes = payload.len().saturating_sub(repeated) as u64;
                bucket.outbound_payload = bucket.outbound_payload.saturating_add(payload_bytes);
                self.outbound_payload_bytes = self.outbound_payload_bytes.saturating_add(payload_bytes);
                let high_entropy = payload_bytes >= 64 && match tcp {
                    TcpPayloadObservation::Partial { fresh, .. } =>
                        crate::net::inspector::shannon_entropy_chunks(
                            fresh.iter().filter_map(|range| payload.get(range.clone())),
                        ) >= 7.2,
                    _ => shannon_entropy(payload) >= 7.2,
                };
                if high_entropy {
                    high_entropy_payload = true;
                    bucket.entropy = bucket.entropy.saturating_add(payload_bytes);
                    self.high_entropy_bytes = self.high_entropy_bytes.saturating_add(payload_bytes);
                    sample_transfer_frame(&mut self.entropy_frames, minute, packet, client_port, retain_entropy);
                }
            }
        } else {
            bucket.inbound = bucket.inbound.saturating_add(length);
            self.inbound_bytes = self.inbound_bytes.saturating_add(length);
            sample_transfer_frame(&mut self.inbound_frames, minute, packet, client_port, retain_volume);
        }
        Some(high_entropy_payload)
    }
}

impl SecurityEngine {
    // ─── C2 Beacon and Exfiltration Correlation ─────────────────────────────

    pub(super) fn check_beacon_and_exfiltration(&mut self, pkt: &Packet, tcp_payload: TcpPayloadObservation, archive_rules: Option<&[String]>) {
        if !pkt.timestamp.is_finite() {
            return;
        }
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
        let scope = scan_scope(pkt);
        // Interleaved capture interfaces need not advance through time together.
        let capture_interface = (scope.0).0;
        self.beacon_flows.retain(|key, state| {
            (key.scope.0).0 != capture_interface || pkt.timestamp - state.last_seen <= BEACON_WINDOW_SECS
        });
        self.exfil_flows.retain(|key, state| {
            (key.scope.0).0 != capture_interface || pkt.timestamp - state.last_seen <= 3600.0
        });
        // A partial retry does not represent one full, independently sized application send.
        if matches!(tcp_payload, TcpPayloadObservation::UnknownOrNew) {
            self.check_periodic_traffic(pkt, scope, archive_rules);
        }
        let mut alerts = Vec::new();
        let source_internal = is_internal_address(&pkt.src);
        let destination_internal = is_internal_address(&pkt.dst);
        let transport;
        if source_internal != destination_internal {
            let outbound = source_internal;
            transport = transfer_transport(pkt);
            // TCP control traffic does not provide a data baseline in either direction.
            if matches!(transport, TransferTransport::Tcp)
                && (matches!(tcp_payload, TcpPayloadObservation::Empty)
                    || (outbound && matches!(tcp_payload, TcpPayloadObservation::Repeat)))
            {
                return;
            }
            let (internal, external) = if outbound {
                (pkt.src.clone(), pkt.dst.clone())
            } else {
                (pkt.dst.clone(), pkt.src.clone())
            };
            let key = ExfilKey {
                internal,
                external,
                destination_port: if outbound { pkt.dst_port } else { pkt.src_port }.unwrap_or(0),
                transport: transport.clone(),
                scope,
            };
            if !self.exfil_flows.contains_key(&key) && !admit_exfil_history(&mut self.exfil_flows, pkt.timestamp) {
                return;
            }
            let state = self.exfil_flows.entry(key).or_default();
            let selected = |id| archive_rules.is_some_and(|rules| rules.iter().any(|rule| rule == id));
            let retain_volume = selected("traffic.asymmetric_outbound");
            let retain_entropy = selected("traffic.high_entropy_outbound");
            let client_port = match transport {
                TransferTransport::Tcp | TransferTransport::Udp =>
                    (if outbound { pkt.src_port } else { pkt.dst_port }).filter(|&port| port != 0),
                _ => None,
            };
            let Some(high_entropy_payload) = state.observe(pkt, outbound, &tcp_payload, client_port, retain_volume, retain_entropy) else { return };

            let volume = if outbound && state.outbound_bytes >= EXFIL_VOLUME_THRESHOLD
                && state.volume_episode.is_none_or(|episode| episode.evidence != VolumeEvidence::BothDirections)
                && u128::from(state.outbound_bytes) >= u128::from(state.inbound_bytes) * 10
            {
                Some(if state.paired_samples() { VolumeEvidence::BothDirections } else { VolumeEvidence::OneWay })
            } else {
                None
            };
            if let Some(evidence) = volume
                && state.volume_episode.is_none_or(|episode| evidence > episode.evidence)
            {
                let opening_frame = state.volume_episode.map_or(pkt.no, |episode| episode.opening_frame);
                state.volume_episode = Some(VolumeEpisode { opening_frame, evidence });
                let (severity, comparison) = match evidence {
                    VolumeEvidence::OneWay => (
                        Severity::Medium, "no paired reverse data baseline observed in the samples; asymmetry unverified".into(),
                    ),
                    VolumeEvidence::BothDirections => (
                        Severity::High,
                        format!("{:.1}:1 service-wide observed ratio across {} captured reverse bytes; at least one cited outbound/reverse pair shares a client port",
                            state.outbound_bytes as f64 / state.inbound_bytes as f64, state.inbound_bytes),
                    ),
                };
                let samples = state.outbound_frames.iter().chain(&state.inbound_frames);
                if retain_volume {
                    self.findings.retained_evidence.extend(samples.clone()
                        .filter(|sample| sample.frame != pkt.no).filter_map(|sample| sample.evidence.as_deref().cloned()));
                }
                alerts.push((
                    "Large asymmetric outbound transfer",
                    severity,
                    format!(
                        "{} to {}: {} captured outbound bytes in the rolling hour, excluding recognized outbound TCP payload retries and payload-free TCP frames in either direction; {comparison}; transfer intent unverified",
                        pkt.src, pkt.dst, state.outbound_bytes
                    ),
                    samples.map(|sample| sample.frame).collect::<Vec<_>>(),
                    opening_frame,
                ));
            }
            if high_entropy_payload
                && !state.entropy_alerted
                && state.high_entropy_bytes >= EXFIL_ENTROPY_THRESHOLD
                && u128::from(state.high_entropy_bytes) * 5 >= u128::from(state.outbound_payload_bytes) * 4
            {
                state.entropy_alerted = true;
                if retain_entropy {
                    self.findings.retained_evidence.extend(state.entropy_frames.iter()
                        .filter(|sample| sample.frame != pkt.no).filter_map(|sample| sample.evidence.as_deref().cloned()));
                }
                let mut sample_ports: HashSet<_> = state.entropy_frames.iter()
                    .filter_map(|sample| sample.client_port).collect();
                let trigger_sampled = state.entropy_frames.iter().any(|sample| sample.frame == pkt.no);
                if !trigger_sampled && let Some(port) = client_port {
                    sample_ports.insert(port);
                }
                let sample_count = state.entropy_frames.len() + usize::from(!trigger_sampled);
                alerts.push((
                    "High-entropy outbound transfer",
                    Severity::Medium,
                    format!(
                        "{} to {}: {} high-entropy outbound transport payload bytes out of {} in the rolling hour, aggregated across client ports to service port {}; distinct client ports in cited frames: {} ({sample_count} frames, not a count of all connections); any attached flow describes the trigger packet only; encryption or compression is possible, and exfiltration is unverified",
                        pkt.src, pkt.dst, state.high_entropy_bytes, state.outbound_payload_bytes,
                        pkt.dst_port.unwrap_or(0), sample_ports.len()
                    ),
                    state.entropy_frames.iter().map(|sample| sample.frame).collect::<Vec<_>>(),
                    pkt.no,
                ));
            }
        } else {
            return;
        }

        for (signature, severity, detail, mut related_packets, opening_frame) in alerts {
            related_packets.retain(|&frame| frame != pkt.no);
            related_packets.sort_unstable();
            related_packets.dedup();
            let correlation_key = format!(
                "{:?}:{transport:?}:[{}]>[{}]:{}:episode:{opening_frame}",
                scope, pkt.src, pkt.dst, pkt.dst_port.unwrap_or(0)
            );
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert { pkt_no: pkt.no, signature, severity, detail },
                related_packets,
                correlation_key: Some(correlation_key),
            });
        }
    }
}
