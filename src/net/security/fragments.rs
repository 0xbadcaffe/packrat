use super::*;

impl SecurityEngine {
    // ─── IPv4 Fragment Integrity ────────────────────────────────────────────

    pub(super) fn check_ipv4_fragments(&mut self, pkt: &Packet) {
        let fragment = match parse_ipv4_fragment(&pkt.bytes) {
            Some(fragment) => fragment,
            None => return,
        };

        self.fragment_states.retain(|_, state| {
            pkt.timestamp < state.last_seen
                || pkt.timestamp - state.last_seen <= FRAGMENT_STATE_TTL_SECS
        });
        if !self.fragment_states.contains_key(&fragment.key)
            && self.fragment_states.len() >= MAX_FRAGMENT_DATAGRAMS
        {
            if let Some(oldest) = self
                .fragment_states
                .iter()
                .min_by(|left, right| left.1.last_seen.total_cmp(&right.1.last_seen))
                .map(|(key, _)| key.clone())
            {
                self.fragment_states.remove(&oldest);
            }
        }

        let mut alerts = Vec::new();
        if fragment.malformed_length {
            alerts.push((
                "Malformed IPv4 fragment",
                Severity::High,
                format!(
                    "IPv4 fragment has a total length smaller than its header from {}",
                    pkt.src
                ),
            ));
        }
        if fragment.more_fragments && fragment.declared_payload_len < 8 {
            alerts.push((
                "Tiny IPv4 fragment",
                Severity::High,
                format!(
                    "IPv4 fragment payload is {} bytes from {}",
                    fragment.declared_payload_len, pkt.src
                ),
            ));
        }

        let state = self
            .fragment_states
            .entry(fragment.key.clone())
            .or_default();
        state.last_seen = pkt.timestamp;
        state.count += 1;

        if !state.overlap_alerted && has_conflicting_fragment_overlap(&state.slices, &fragment) {
            state.overlap_alerted = true;
            alerts.push((
                "Conflicting IPv4 fragments",
                Severity::Critical,
                format!(
                    "Overlapping IPv4 fragments carry different bytes from {} to {}",
                    pkt.src, pkt.dst
                ),
            ));
        }

        if !fragment.payload.is_empty() {
            state.slices.push(FragmentSlice {
                start: fragment.offset,
                data: fragment.payload.to_vec(),
            });
        }

        if state.count > MAX_FRAGMENTS_PER_DATAGRAM && !state.flood_alerted {
            state.flood_alerted = true;
            alerts.push((
                "IPv4 fragment flood",
                Severity::High,
                format!(
                    "More than {MAX_FRAGMENTS_PER_DATAGRAM} fragments for one datagram from {}",
                    pkt.src
                ),
            ));
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

    // ─── TCP Integrity / Evasion ────────────────────────────────────────────

    pub(super) fn check_tcp_integrity(&mut self, pkt: &Packet) {
        let segment = match parse_ipv4_tcp_frame(&pkt.bytes) {
            Some(TcpFrame::Segment(segment)) => segment,
            Some(TcpFrame::Malformed(reason)) => {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "Malformed TCP header",
                    severity: Severity::High,
                    detail: format!("{reason} from {} to {}", pkt.src, pkt.dst),
                });
                return;
            }
            None => return,
        };

        const FIN: u8 = 0x01;
        const SYN: u8 = 0x02;
        const RST: u8 = 0x04;
        if segment.flags & SYN != 0 && segment.flags & (FIN | RST) != 0 {
            self.push_ids(IdsAlert {
                pkt_no: pkt.no,
                signature: "Illegal TCP flag combination",
                severity: Severity::High,
                detail: format!(
                    "TCP SYN combined with FIN or RST from {} to {}",
                    pkt.src, pkt.dst
                ),
            });
        }

        self.tcp_integrity.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= TCP_STATE_TTL_SECS
        });
        if !self.tcp_integrity.contains_key(&segment.key)
            && self.tcp_integrity.len() >= MAX_TCP_FLOWS
        {
            if let Some(oldest) = self
                .tcp_integrity
                .iter()
                .min_by(|left, right| left.1.last_seen.total_cmp(&right.1.last_seen))
                .map(|(key, _)| key.clone())
            {
                self.tcp_integrity.remove(&oldest);
            }
        }

        let mut alerts = Vec::new();
        let state = self.tcp_integrity.entry(segment.key.clone()).or_default();
        state.last_seen = pkt.timestamp;

        if segment.flags & SYN != 0 {
            state.from_a.clear();
            state.from_b.clear();
            state.reset_seen = false;
            state.overlap_alerted = false;
            state.post_reset_alerted = false;
        }

        if state.reset_seen && !segment.payload.is_empty() && !state.post_reset_alerted {
            state.post_reset_alerted = true;
            alerts.push((
                "TCP payload after reset",
                Severity::High,
                format!(
                    "Payload continued after an observed TCP reset from {} to {}",
                    pkt.src, pkt.dst
                ),
            ));
        }

        let slices = if segment.from_a {
            &mut state.from_a
        } else {
            &mut state.from_b
        };
        if !segment.payload.is_empty() {
            if !state.overlap_alerted && has_conflicting_tcp_overlap(slices, &segment) {
                state.overlap_alerted = true;
                alerts.push((
                    "Conflicting TCP retransmission",
                    Severity::Critical,
                    format!(
                        "Overlapping TCP sequence ranges contain different bytes from {} to {}",
                        pkt.src, pkt.dst
                    ),
                ));
            }
            if slices.len() < MAX_TCP_SLICES_PER_DIRECTION {
                slices.push(FragmentSlice {
                    start: segment.sequence,
                    data: segment.payload.to_vec(),
                });
            }
        }

        if segment.flags & RST != 0 {
            state.reset_seen = true;
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
