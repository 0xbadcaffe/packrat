use super::*;

impl SecurityEngine {
    // ─── IPv4 Fragment Integrity ────────────────────────────────────────────

    pub(super) fn check_ipv4_fragments(&mut self, pkt: &Packet) {
        let fragment = match parse_ipv4_fragment(&pkt.bytes) {
            Some(fragment) => fragment,
            None => return,
        };

        let key = (service_scope(pkt), fragment.key.clone());
        self.fragment_states.retain(|_, state| {
            pkt.timestamp < state.last_seen
                || pkt.timestamp - state.last_seen <= FRAGMENT_STATE_TTL_SECS
        });
        if !self.fragment_states.contains_key(&key)
            && self.fragment_states.len() >= MAX_FRAGMENT_DATAGRAMS
        {
            if let Some(oldest) = self
                .fragment_states
                .iter()
                .min_by(|left, right| {
                    left.1.last_seen.total_cmp(&right.1.last_seen).then(left.0.cmp(right.0))
                })
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
            .entry(key.clone())
            .or_default();
        state.last_seen = state.last_seen.max(pkt.timestamp);
        state.count = state.count.saturating_add(1);

        let conflict = if !state.overlap_alerted && !fragment.malformed_length
            && let Some(frame) = conflicting_fragment_frame(&state.slices, &fragment)
        {
            state.overlap_alerted = true;
            Some(frame)
        } else { None };
        if !fragment.malformed_length {
            state.remember(pkt.no, fragment.offset, fragment.payload);
        }

        if state.count > MAX_FRAGMENTS_PER_DATAGRAM && !state.flood_alerted {
            state.flood_alerted = true;
            alerts.push((
                "IPv4 fragment flood",
                Severity::High,
                format!(
                    "More than {MAX_FRAGMENTS_PER_DATAGRAM} fragment observations for one datagram key from {}",
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
        if let Some(frame) = conflict {
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: "Conflicting IPv4 fragments",
                    severity: Severity::High,
                    detail: format!(
                        "Overlapping IPv4 fragments #{} and #{} carry different bytes from {} to {}; receiver behavior unverified",
                        frame, pkt.no, pkt.src, pkt.dst,
                    ),
                },
                related_packets: vec![frame],
                correlation_key: Some(format!("{key:?}")),
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

        if !segment.complete {
            return;
        }
        let scope = service_scope(pkt);
        let key = (scope, segment.key.clone());
        self.tcp_integrity.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= TCP_STATE_TTL_SECS
        });
        if !self.tcp_integrity.contains_key(&key)
            && self.tcp_integrity.len() >= MAX_TCP_FLOWS
        {
            if let Some(oldest) = self
                .tcp_integrity
                .iter()
                .min_by(|left, right| {
                    left.1.last_seen.total_cmp(&right.1.last_seen).then(left.0.cmp(right.0))
                })
                .map(|(key, _)| key.clone())
            {
                self.tcp_integrity.remove(&oldest);
            }
        }

        let state = self.tcp_integrity.entry(key).or_default();
        let in_time_order = pkt.timestamp >= state.last_seen;
        state.last_seen = state.last_seen.max(pkt.timestamp);

        if in_time_order && segment.flags & (SYN | RST) == SYN {
            state.from_a.clear();
            state.from_b.clear();
            state.reset = None;
            state.overlap_alerted = false;
            state.post_reset_alerted = false;
        }

        let slices = if segment.from_a {
            &mut state.from_a
        } else {
            &mut state.from_b
        };
        let mut post_reset = None;
        let mut overlap = None;
        if !segment.payload.is_empty() {
            if !state.post_reset_alerted
                && segment.flags & RST == 0
                && let Some(reset) = state.reset
                && (0.0..=TCP_STATE_TTL_SECS).contains(&(pkt.timestamp - reset.timestamp))
                && !slices.iter().any(|slice| {
                    slice.start == segment.sequence && slice.data == segment.payload
                })
            {
                state.post_reset_alerted = true;
                post_reset = Some(reset);
            }
            if !state.overlap_alerted && has_conflicting_tcp_overlap(slices, &segment) {
                state.overlap_alerted = true;
                overlap = Some(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "Conflicting TCP retransmission",
                    severity: Severity::Critical,
                    detail: format!(
                        "Overlapping TCP sequence ranges contain different bytes from {} to {}",
                        pkt.src, pkt.dst
                    ),
                });
            }
            if slices.len() < MAX_TCP_SLICES_PER_DIRECTION {
                slices.push(FragmentSlice {
                    packet_no: pkt.no,
                    start: segment.sequence,
                    data: segment.payload.to_vec(),
                });
            }
        }

        if in_time_order && segment.flags & (SYN | FIN | RST) == RST {
            state.reset = Some(TcpResetObservation {
                packet_no: pkt.no,
                timestamp: pkt.timestamp,
                sequence: segment.sequence,
                from_a: segment.from_a,
            });
        }

        if let Some(reset) = post_reset {
            let (src, dst) = if segment.from_a {
                (segment.key.endpoint_a, segment.key.endpoint_b)
            } else {
                (segment.key.endpoint_b, segment.key.endpoint_a)
            };
            let direction = if reset.from_a == segment.from_a { "same" } else { "opposite" };
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: "TCP payload after reset",
                    severity: Severity::Medium,
                    detail: format!(
                        "TCP {}:{} to {}:{}: payload seq {} followed reset frame #{} ({} direction, seq {}); reset acceptance and on-wire ordering unverified",
                        std::net::Ipv4Addr::from(src.0), src.1, std::net::Ipv4Addr::from(dst.0), dst.1,
                        segment.sequence, reset.packet_no, direction, reset.sequence,
                    ),
                },
                related_packets: vec![reset.packet_no],
                correlation_key: Some(format!("{scope:?}:{:?}", segment.key)),
            });
        }
        if let Some(alert) = overlap {
            self.push_ids(alert);
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/security_fragment_state_tests.rs"]
mod tests;
