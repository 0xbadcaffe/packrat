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

    /// Returns true for a complete TCP segment verified to have no new payload.
    pub(super) fn check_tcp_integrity(&mut self, pkt: &Packet) -> bool {
        if !pkt.timestamp.is_finite() ||
            pkt.capture.as_ref().is_some_and(|meta| !crate::net::parser::supports_capture_link_type(meta.link_type))
        {
            return false;
        }
        let segment = match parse_ipv4_tcp_frame(&pkt.bytes).or_else(|| parse_ipv6_tcp_frame(&pkt.bytes)) {
            Some(TcpFrame::Segment(segment)) => segment,
            Some(TcpFrame::Malformed(reason)) => {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "Malformed TCP header",
                    severity: Severity::High,
                    detail: format!("{reason} from {} to {}", pkt.src, pkt.dst),
                });
                return false;
            }
            None => return false,
        };

        const FIN: u8 = 0x01;
        const SYN: u8 = 0x02;
        const RST: u8 = 0x04;
        const ACK: u8 = 0x10;
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
            return false;
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
        if state.started_at.is_some_and(|start| pkt.timestamp < start) {
            return segment.payload.is_empty();
        }
        let in_time_order = pkt.timestamp >= state.last_seen;
        state.last_seen = state.last_seen.max(pkt.timestamp);

        let direction = usize::from(!segment.from_a);
        if in_time_order && segment.flags & (SYN | ACK | FIN | RST) == SYN {
            let opening = state.opening_sequences[direction];
            if opening != Some(segment.sequence) {
                // The other peer can send an opening SYN before either side acknowledges.
                if state.started_at.is_none() || state.past_opening || opening.is_some() {
                    *state = TcpIntegrityState {
                        last_seen: pkt.timestamp,
                        started_at: Some(pkt.timestamp),
                        ..Default::default()
                    };
                }
                state.opening_sequences[direction] = Some(segment.sequence);
            }
        } else if in_time_order && segment.flags & SYN == 0 {
            state.past_opening |= segment.flags & (ACK | FIN | RST) != 0 || !segment.payload.is_empty();
        }

        let slices = if segment.from_a {
            &mut state.from_a
        } else {
            &mut state.from_b
        };
        let mut post_reset = None;
        let mut overlap = None;
        let mut duplicate = false;
        if !segment.payload.is_empty() {
            let payload_sequence = segment.sequence.wrapping_add(u32::from(segment.flags & SYN != 0));
            duplicate = slices.contains(payload_sequence, segment.payload);
            if !state.post_reset_alerted
                && segment.flags & RST == 0
                && let Some(reset) = state.reset
                && (0.0..=TCP_STATE_TTL_SECS).contains(&(pkt.timestamp - reset.timestamp))
                && !duplicate
                && !tcp_payload_already_seen(&slices.slices, payload_sequence, segment.payload)
            {
                state.post_reset_alerted = true;
                post_reset = Some(reset);
            }
            if !state.overlap_alerted
                && !duplicate
                && let Some(conflict) = conflicting_tcp_overlap(&slices.slices, payload_sequence, segment.payload)
            {
                state.overlap_alerted = true;
                overlap = Some(conflict);
            }
            if !duplicate && (!state.overlap_alerted || !state.post_reset_alerted) {
                slices.remember_distinct(pkt.no, payload_sequence, segment.payload);
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
                        "TCP {} to {}: payload seq {} followed reset frame #{} ({} direction, seq {}); reset acceptance and on-wire ordering unverified",
                        src, dst,
                        segment.sequence, reset.packet_no, direction, reset.sequence,
                    ),
                },
                related_packets: vec![reset.packet_no],
                correlation_key: Some(format!("{scope:?}:{:?}:reset:{}", segment.key, reset.packet_no)),
            });
        }
        if let Some(conflict) = overlap {
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: "Conflicting TCP retransmission",
                    severity: Severity::High,
                    detail: format!(
                        "Frames #{} and #{} from {} to {} differ at TCP sequence {} ({} overlapping bytes compared); receiver outcome unverified",
                        conflict.previous_frame, pkt.no, pkt.src, pkt.dst,
                        conflict.difference_sequence, conflict.compared_bytes,
                    ),
                },
                related_packets: vec![conflict.previous_frame],
                correlation_key: Some(format!(
                    "{scope:?}:{:?}:{}:{}", segment.key, segment.from_a, conflict.previous_frame
                )),
            });
        }
        segment.payload.is_empty() || duplicate
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/security_fragment_state_tests.rs"]
mod tests;
