use super::*;
use super::fragments::TcpPayloadObservation;
use super::scans::scan_scope;
use std::collections::VecDeque;

const MAX_CANDIDATE_FRAME_COST: usize = 2 * 1024;
const MAX_PERIODIC_DIRECTION_COST: usize = 16 * 1024;
const MAX_TRANSFER_SAMPLE_FRAMES: usize = 8;

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct BehaviorFlowKey {
    first: (String, u16),
    second: (String, u16),
    transport: &'static str,
    scope: ScanScope,
}

#[derive(Debug)]
pub(super) struct BeaconSample {
    pub(super) timestamp: f64,
    pub(super) size: u32,
    pub(super) payload_length: u16,
    packet_no: u64,
}

#[derive(Debug, Default)]
pub(super) struct BeaconState {
    directions: [BeaconDirection; 2],
    pub(super) last_seen: f64,
    episode: Option<BeaconEpisode>,
    rearmed_at: Option<f64>,
}

#[derive(Debug, Default)]
struct BeaconDirection {
    samples: Vec<BeaconSample>,
    retained: VecDeque<(Packet, usize)>,
    retained_cost: usize,
}

impl BeaconDirection {
    fn remember(&mut self, packet: &Packet) {
        let cost = crate::model::project::pinned_packet_cost(packet);
        let fits = cost <= MAX_CANDIDATE_FRAME_COST;
        let oldest = self.samples.first().map_or(packet.timestamp, |sample| sample.timestamp);
        while self.retained.front().is_some_and(|(prior, _)| prior.timestamp < oldest)
            || (fits && self.retained_cost + cost > MAX_PERIODIC_DIRECTION_COST)
        {
            let Some((_, removed)) = self.retained.pop_front() else { break; };
            self.retained_cost -= removed;
        }
        if fits {
            self.retained.push_back((packet.clone(), cost));
            self.retained_cost += cost;
        }
    }
}

#[derive(Debug)]
struct BeaconEpisode {
    direction: usize,
    last_seen: f64,
    previous_size_sample_at: f64,
    sizes: std::ops::RangeInclusive<u32>,
    gaps: std::ops::RangeInclusive<f64>,
}

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
    frame: u64,
    evidence: Option<Box<Packet>>,
}

fn sample_transfer_frame(frames: &mut VecDeque<TransferSample>, minute: i64, packet: &Packet, retain: bool) {
    if frames.len() == MAX_TRANSFER_SAMPLE_FRAMES {
        frames.pop_front();
    }
    frames.push_back(TransferSample {
        minute,
        frame: packet.no,
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
    fn observe(
        &mut self, packet: &Packet, outbound: bool, tcp: &TcpPayloadObservation,
        retain_volume: bool, retain_entropy: bool,
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
            sample_transfer_frame(&mut self.outbound_frames, minute, packet, retain_volume);
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
                    sample_transfer_frame(&mut self.entropy_frames, minute, packet, retain_entropy);
                }
            }
        } else {
            bucket.inbound = bucket.inbound.saturating_add(length);
            self.inbound_bytes = self.inbound_bytes.saturating_add(length);
            sample_transfer_frame(&mut self.inbound_frames, minute, packet, retain_volume);
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
        self.beacon_flows.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= BEACON_WINDOW_SECS
        });
        self.exfil_flows.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= 3600.0
        });
        let scope = scan_scope(pkt);
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
            // Keep observed reverse bytes; omit verified empty segments and recognized outbound retries.
            if outbound && matches!(transport, TransferTransport::Tcp)
                && matches!(tcp_payload, TcpPayloadObservation::Repeat | TcpPayloadObservation::Empty)
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
            if !self.exfil_flows.contains_key(&key) {
                evict_oldest_exfil(&mut self.exfil_flows);
            }
            let state = self.exfil_flows.entry(key).or_default();
            let selected = |id| archive_rules.is_some_and(|rules| rules.iter().any(|rule| rule == id));
            let retain_volume = selected("traffic.asymmetric_outbound");
            let retain_entropy = selected("traffic.high_entropy_outbound");
            let Some(high_entropy_payload) = state.observe(pkt, outbound, &tcp_payload, retain_volume, retain_entropy) else { return };

            let volume = match state.inbound_bytes {
                0 => Some(VolumeEvidence::OneWay),
                received if u128::from(state.outbound_bytes) >= u128::from(received) * 10 => Some(VolumeEvidence::BothDirections),
                _ => None,
            };
            if outbound && state.outbound_bytes >= EXFIL_VOLUME_THRESHOLD
                && let Some(evidence) = volume
                && state.volume_episode.is_none_or(|episode| evidence > episode.evidence)
            {
                let opening_frame = state.volume_episode.map_or(pkt.no, |episode| episode.opening_frame);
                state.volume_episode = Some(VolumeEpisode { opening_frame, evidence });
                let (severity, comparison) = match evidence {
                    VolumeEvidence::OneWay => (
                        Severity::Medium, "no reverse bytes observed; asymmetry unverified".into(),
                    ),
                    VolumeEvidence::BothDirections => (
                        Severity::High,
                        format!("{:.1}:1 observed ratio across {} captured reverse bytes",
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
                        "{} to {}: {} captured outbound bytes in the rolling hour, excluding recognized outbound TCP payload retries and payload-free TCP frames; {comparison}; transfer intent unverified",
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
                alerts.push((
                    "High-entropy outbound transfer",
                    Severity::Medium,
                    format!(
                        "{} to {}: {} high-entropy outbound transport payload bytes out of {} in the rolling hour, aggregated across client ports to service port {}; attached flow describes the trigger packet only; encryption or compression is possible, and exfiltration is unverified",
                        pkt.src, pkt.dst, state.high_entropy_bytes, state.outbound_payload_bytes,
                        pkt.dst_port.unwrap_or(0)
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

    fn check_periodic_traffic(&mut self, pkt: &Packet, scope: ScanScope, archive_rules: Option<&[String]>) {
        let (Some(source_port @ 1..), Some(destination_port @ 1..)) = (pkt.src_port, pkt.dst_port) else {
            return;
        };
        let ports = (source_port, destination_port);
        let (transport, payload_length) = if let Some((_, payload)) =
            crate::analysis::stream::tcp_payload_with_ack(pkt, ports).filter(|(_, payload)| !payload.is_empty())
        {
            ("TCP", payload.len())
        } else if let Some((_, _, payload)) = crate::analysis::dns_transactions::udp_payload(pkt)
            .filter(|(src, dst, payload)| (*src, *dst) == ports && !payload.is_empty())
        {
            ("UDP", payload.len())
        } else {
            return;
        };
        let Ok(payload_length) = u16::try_from(payload_length) else { return };
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
            transport,
            scope,
        };
        if !self.beacon_flows.contains_key(&key) {
            evict_oldest_beacon(&mut self.beacon_flows);
        }
        let state = self.beacon_flows.entry(key).or_default();
        state.last_seen = state.last_seen.max(pkt.timestamp);
        let size = pkt.capture.as_ref().map_or(u32::from(pkt.length), |meta| meta.wire_length);
        if state.rearmed_at.is_some_and(|at| pkt.timestamp < at) {
            return;
        }
        if let Some(episode) = &mut state.episode {
            if pkt.timestamp - episode.last_seen > BEACON_WINDOW_SECS {
                state.episode = None;
                state.directions = Default::default();
                state.rearmed_at = Some(pkt.timestamp);
            } else {
                if direction == episode.direction && episode.sizes.contains(&size)
                    && pkt.timestamp > episode.previous_size_sample_at
                {
                    if episode.gaps.contains(&(pkt.timestamp - episode.previous_size_sample_at)) {
                        episode.last_seen = pkt.timestamp;
                    }
                    episode.previous_size_sample_at = pkt.timestamp;
                }
                return;
            }
        }
        let window = &mut state.directions[direction];
        let samples = &mut window.samples;
        if samples.last().is_some_and(|sample| pkt.timestamp <= sample.timestamp) {
            return;
        }
        samples.retain(|sample| pkt.timestamp - sample.timestamp <= BEACON_WINDOW_SECS);
        if samples.len() == 32 {
            samples.remove(0);
        }
        samples.push(BeaconSample {
            timestamp: pkt.timestamp,
            size,
            payload_length,
            packet_no: pkt.no,
        });
        let window_match = if let Some(stats) = beacon_pattern(samples) {
            Some((samples.as_slice(), stats))
        } else if samples.len() > BEACON_MIN_SAMPLES {
            let recent = &samples[samples.len() - BEACON_MIN_SAMPLES..];
            beacon_pattern(recent).map(|stats| (recent, stats))
        } else {
            None
        };
        let retain = archive_rules.is_some_and(|rules| rules.iter().any(|rule| rule == "traffic.periodic_fixed_size"));
        let Some((evidence, stats)) = window_match else {
            if retain { window.remember(pkt); }
            return;
        };
        let margin = stats.size_max.div_ceil(10);
        let jitter = stats.interval_mean * 0.15;
        state.episode = Some(BeaconEpisode { direction, last_seen: pkt.timestamp,
            previous_size_sample_at: pkt.timestamp,
            sizes: stats.size_min.saturating_sub(margin)..=stats.size_max.saturating_add(margin),
            gaps: (stats.interval_min - jitter).max(0.0)..=(stats.interval_max + jitter) });
        let related_packets: Vec<_> = evidence[..evidence.len() - 1]
            .iter()
            .map(|sample| sample.packet_no)
            .collect();
        let count = evidence.len();
        if retain {
            self.findings.retained_evidence.extend(window.retained.drain(..)
                .filter_map(|(packet, _)| related_packets.contains(&packet.no).then_some(packet)));
        }
        state.directions = Default::default();
        self.push_ids_finding(IdsFinding {
            alert: IdsAlert {
                pkt_no: pkt.no,
                signature: "Periodic fixed-size traffic",
                severity: Severity::Medium,
                detail: format!(
                    "{count} {transport} packets from [{}]:{source_port} to [{}]:{destination_port} over {:.1}s; gaps {:.1}-{:.1}s (mean {:.1}s), sizes {}-{} bytes on wire, {}-{} captured payload bytes per packet. Timing alone does not establish command-and-control.",
                    pkt.src, pkt.dst, stats.duration, stats.interval_min, stats.interval_max,
                    stats.interval_mean, stats.size_min, stats.size_max, stats.payload_min, stats.payload_max,
                ),
            },
            related_packets,
            correlation_key: Some(format!(
                "{} {scope:?} [{}]:{}<>[{}]:{}:episode:{}",
                transport, first.0, first.1, second.0, second.1, pkt.no,
            )),
        });
    }

}

#[cfg(test)]
#[path = "../../../tests/unit/periodic_evidence_cache_tests.rs"]
mod evidence_cache_tests;
