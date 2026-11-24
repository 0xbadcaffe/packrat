use super::behavior::MAX_CANDIDATE_FRAME_COST;
use super::*;
use std::collections::VecDeque;

const MAX_PERIODIC_DIRECTION_COST: usize = 16 * 1024;

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct BehaviorFlowKey {
    first: (String, u16),
    second: (String, u16),
    transport: &'static str,
    pub(super) scope: ScanScope,
}

impl BehaviorFlowKey {
    fn for_packet(packet: &Packet, ports: (u16, u16), transport: &'static str, scope: ScanScope) -> (Self, usize) {
        let source = (packet.src.as_str(), ports.0);
        let destination = (packet.dst.as_str(), ports.1);
        let (first, second, direction) = if source <= destination {
            (source, destination, 0)
        } else {
            (destination, source, 1)
        };
        (Self {
            first: (first.0.into(), first.1),
            second: (second.0.into(), second.1),
            transport,
            scope,
        }, direction)
    }
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

impl SecurityEngine {
    pub(super) fn start_periodic_tcp_connection(&mut self, pkt: &Packet, scope: ScanScope) {
        let Some(ports) = pkt.src_port.zip(pkt.dst_port) else { return };
        let (key, _) = BehaviorFlowKey::for_packet(pkt, ports, "TCP", scope);
        if let Some(state) = self.beacon_flows.get_mut(&key).filter(|state| pkt.timestamp >= state.last_seen) {
            *state = BeaconState { last_seen: pkt.timestamp, rearmed_at: Some(pkt.timestamp), ..Default::default() };
        }
    }

    pub(super) fn check_periodic_traffic(&mut self, pkt: &Packet, scope: ScanScope, archive_rules: Option<&[String]>) {
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
        let (key, direction) = BehaviorFlowKey::for_packet(pkt, ports, transport, scope);
        if !self.beacon_flows.contains_key(&key) {
            evict_oldest_beacon(&mut self.beacon_flows);
        }
        let (first, second) = if direction == 0 {
            ((pkt.src.as_str(), source_port), (pkt.dst.as_str(), destination_port))
        } else {
            ((pkt.dst.as_str(), destination_port), (pkt.src.as_str(), source_port))
        };
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
