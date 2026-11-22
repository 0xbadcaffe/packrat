use super::*;

fn sample_transfer_frame(frames: &mut std::collections::VecDeque<(i64, u64)>, minute: i64, frame: u64) {
    if frames.len() == 8 {
        frames.pop_front();
    }
    frames.push_back((minute, frame));
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

impl ExfilState {
    fn observe(&mut self, packet: &Packet, outbound: bool, count_payload: bool) -> Option<bool> {
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
                frames.retain(|&(minute, _)| minute >= cutoff);
            }
            self.volume_alerted &= self.outbound_bytes >= EXFIL_VOLUME_THRESHOLD / 2;
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
        let length = u64::from(packet.length);
        let mut high_entropy_payload = false;
        if outbound {
            bucket.outbound = bucket.outbound.saturating_add(length);
            self.outbound_bytes = self.outbound_bytes.saturating_add(length);
            sample_transfer_frame(&mut self.outbound_frames, minute, packet.no);
            if count_payload && let Some(payload) = observed_transport_payload(packet) {
                let payload_bytes = payload.len() as u64;
                bucket.outbound_payload = bucket.outbound_payload.saturating_add(payload_bytes);
                self.outbound_payload_bytes = self.outbound_payload_bytes.saturating_add(payload_bytes);
                if payload.len() >= 64 && shannon_entropy(payload) >= 7.2 {
                    high_entropy_payload = true;
                    bucket.entropy = bucket.entropy.saturating_add(payload_bytes);
                    self.high_entropy_bytes = self.high_entropy_bytes.saturating_add(payload_bytes);
                    sample_transfer_frame(&mut self.entropy_frames, minute, packet.no);
                }
            }
        } else {
            bucket.inbound = bucket.inbound.saturating_add(length);
            self.inbound_bytes = self.inbound_bytes.saturating_add(length);
            sample_transfer_frame(&mut self.inbound_frames, minute, packet.no);
        }
        Some(high_entropy_payload)
    }
}

impl SecurityEngine {
    // ─── C2 Beacon and Exfiltration Correlation ─────────────────────────────

    pub(super) fn check_beacon_and_exfiltration(&mut self, pkt: &Packet, no_new_tcp_payload: bool) {
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
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= 3600.0
        });
        self.exfil_flows.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= 3600.0
        });
        if !no_new_tcp_payload {
            self.check_periodic_traffic(pkt);
        }
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
                scope: service_scope(pkt),
            };
            if !self.exfil_flows.contains_key(&key) {
                evict_oldest_exfil(&mut self.exfil_flows);
            }
            let state = self.exfil_flows.entry(key).or_default();
            let Some(high_entropy_payload) = state.observe(pkt, outbound, !no_new_tcp_payload) else { return };

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
                        "{} to {}: {} captured outbound bytes with {:.1}:1 ratio in the rolling hour",
                        pkt.src, pkt.dst, state.outbound_bytes, outbound_ratio
                    ),
                    state.outbound_frames.iter().chain(&state.inbound_frames).map(|&(_, frame)| frame).collect::<Vec<_>>(),
                ));
            }
            if high_entropy_payload
                && !state.entropy_alerted
                && state.high_entropy_bytes >= EXFIL_ENTROPY_THRESHOLD
                && u128::from(state.high_entropy_bytes) * 5 >= u128::from(state.outbound_payload_bytes) * 4
            {
                state.entropy_alerted = true;
                alerts.push((
                    "High-entropy outbound transfer",
                    Severity::High,
                    format!(
                        "{} to {}: {} high-entropy outbound transport payload bytes in the rolling hour",
                        pkt.src, pkt.dst, state.high_entropy_bytes
                    ),
                    state.entropy_frames.iter().map(|&(_, frame)| frame).collect::<Vec<_>>(),
                ));
            }
        }

        for (signature, severity, detail, mut related_packets) in alerts {
            related_packets.retain(|&frame| frame != pkt.no);
            related_packets.sort_unstable();
            related_packets.dedup();
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert { pkt_no: pkt.no, signature, severity, detail },
                related_packets,
                correlation_key: Some(format!(
                    "{:?}:{}:[{}]>[{}]:{}",
                    service_scope(pkt), pkt.protocol, pkt.src, pkt.dst, pkt.dst_port.unwrap_or(0)
                )),
            });
        }
    }

    fn check_periodic_traffic(&mut self, pkt: &Packet) {
        let (Some(source_port), Some(destination_port)) = (pkt.src_port, pkt.dst_port) else {
            return;
        };
        let ports = (source_port, destination_port);
        let transport = if crate::analysis::stream::tcp_data_port_pair(pkt) == Some(ports) {
            "TCP"
        } else if crate::analysis::dns_transactions::udp_payload(pkt)
            .is_some_and(|(src, dst, _)| (src, dst) == ports)
        {
            "UDP"
        } else {
            return;
        };
        let source = (pkt.src.as_str(), source_port);
        let destination = (pkt.dst.as_str(), destination_port);
        let (first, second, direction) = if source <= destination {
            (source, destination, 0)
        } else {
            (destination, source, 1)
        };
        let scope = service_scope(pkt);
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
            size: pkt.capture.as_ref().map_or(u32::from(pkt.length), |meta| meta.wire_length),
            packet_no: pkt.no,
        });
        let (evidence, stats) = if let Some(stats) = beacon_pattern(samples) {
            (samples.as_slice(), stats)
        } else if samples.len() > BEACON_MIN_SAMPLES {
            let recent = &samples[samples.len() - BEACON_MIN_SAMPLES..];
            let Some(stats) = beacon_pattern(recent) else {
                return;
            };
            (recent, stats)
        } else {
            return;
        };
        state.alerted = true;
        let related_packets = evidence[..evidence.len() - 1]
            .iter()
            .map(|sample| sample.packet_no)
            .collect();
        let count = evidence.len();
        self.push_ids_finding(IdsFinding {
            alert: IdsAlert {
                pkt_no: pkt.no,
                signature: "Periodic fixed-size traffic",
                severity: Severity::Medium,
                detail: format!(
                    "{count} packets from [{}]:{source_port} to [{}]:{destination_port} over {:.1}s; gaps {:.1}-{:.1}s (mean {:.1}s), sizes {}-{} bytes. Timing alone does not establish command-and-control.",
                    pkt.src, pkt.dst, stats.duration, stats.interval_min, stats.interval_max,
                    stats.interval_mean, stats.size_min, stats.size_max,
                ),
            },
            related_packets,
            correlation_key: Some(format!(
                "{} {scope:?} [{}]:{}<>[{}]:{}",
                transport, first.0, first.1, second.0, second.1,
            )),
        });
    }

    pub(super) fn check_ntlm_fanout(&mut self, pkt: &Packet) {
        let (Some(source_port), Some(445)) = (pkt.src_port, pkt.dst_port) else { return };
        if !pkt.timestamp.is_finite()
            || !is_internal_address(&pkt.src)
            || !is_internal_address(&pkt.dst)
            || !crate::analysis::stream::tcp_payload_with_ack(pkt, (source_port, 445))
                .is_some_and(|(_, payload)| smb_wire::has_ntlm_authenticate(payload))
        {
            return;
        }
        self.ntlm_fanout.retain(|_, state| pkt.timestamp - state.last_seen <= 300.0);
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
