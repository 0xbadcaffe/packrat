use super::*;

pub(super) enum TcpPayloadObservation {
    UnknownOrNew,
    Empty,
    Repeat,
    Partial { fresh: Vec<std::ops::Range<usize>>, repeated_bytes: usize },
}

impl SecurityEngine {
    // ─── IPv4 Fragment Integrity ────────────────────────────────────────────

    pub(super) fn check_ipv4_fragments(&mut self, pkt: &Packet, archive_rules: Option<&[String]>) {
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

        let conflict = if !state.overlap_alerted && !fragment.malformed_length
            && let Some(frame) = conflicting_fragment_frame(&state.slices, &fragment)
        {
            state.overlap_alerted = true;
            Some(frame)
        } else { None };
        let compare = !fragment.malformed_length && state.remember(pkt.no, fragment.offset, fragment.payload);
        let offsets_before = state.offset_frames.len();
        let burst = state.observe_offset(pkt.no, &fragment);
        let counted = state.offset_frames.len() > offsets_before;
        let retain_burst = counted && archive_rules.is_some_and(|rules| {
            rules.iter().any(|rule| rule == "ipv4.fragment_observation_burst")
        });
        let retain_current = archive_rules.is_some() && ((compare && !state.overlap_alerted) || retain_burst);

        if let Some(related_packets) = burst {
            if retain_burst {
                self.findings.retained_evidence.extend(related_packets.iter().filter_map(|&frame| {
                    self.ipv4_fragment_evidence.cited_packet(pkt, frame).cloned()
                }));
            }
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: "IPv4 fragment flood",
                    severity: Severity::Medium,
                    detail: format!(
                        "Captured {} distinct fragment offsets for IPv4 ID 0x{:04x} from {} to {}; resource impact unverified",
                        MAX_FRAGMENTS_PER_DATAGRAM + 1, fragment.key.identification, pkt.src, pkt.dst,
                    ),
                },
                related_packets,
                correlation_key: Some(format!("{key:?}:{}", pkt.no)),
            });
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
            if archive_rules.is_some() && let Some(prior) = self.ipv4_fragment_evidence.cited_packet(pkt, frame) {
                self.findings.retained_evidence.push(prior.clone());
            }
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
        if retain_current {
            self.ipv4_fragment_evidence.remember(pkt);
        }
    }

    // ─── TCP Integrity / Evasion ────────────────────────────────────────────

    pub(super) fn check_tcp_integrity(&mut self, pkt: &Packet, archive_rules: Option<&[String]>) -> TcpPayloadObservation {
        use TcpPayloadObservation::{Empty, Repeat, UnknownOrNew};
        const MAX_RESET_EVIDENCE_BYTES: usize = 2_048;
        let retain_reset = || archive_rules.is_some_and(|rules| rules.iter().any(|rule| rule == "tcp.payload_after_observed_reset"));
        if !pkt.timestamp.is_finite() ||
            pkt.capture.as_ref().is_some_and(|meta| !crate::net::parser::supports_capture_link_type(meta.link_type))
        {
            return UnknownOrNew;
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
                return UnknownOrNew;
            }
            None => return UnknownOrNew,
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
            return UnknownOrNew;
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
            return if segment.payload.is_empty() { Empty } else { UnknownOrNew };
        }
        let in_time_order = observation_precedes(
            (state.last_seen, state.last_seen_frame), (pkt.timestamp, pkt.no),
        );
        if in_time_order {
            state.last_seen = pkt.timestamp;
            state.last_seen_frame = pkt.no;
            if state.reset_evidence.is_some() && state.reset.is_some_and(|reset| pkt.timestamp - reset.timestamp > TCP_STATE_TTL_SECS) {
                state.reset_evidence = None;
            }
        }

        let direction = usize::from(!segment.from_a);
        if in_time_order && segment.flags & (SYN | ACK | FIN | RST) == SYN {
            let opening = state.opening_sequences[direction];
            if opening != Some(segment.sequence) {
                // The other peer can send an opening SYN before either side acknowledges.
                if state.started_at.is_none() || state.past_opening || opening.is_some() {
                    *state = TcpIntegrityState {
                        last_seen: pkt.timestamp,
                        last_seen_frame: pkt.no,
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
        let mut payload_observation = Empty;
        if !segment.payload.is_empty() {
            let payload_sequence = segment.sequence.wrapping_add(u32::from(segment.flags & SYN != 0));
            let duplicate = slices.contains(payload_sequence, segment.payload);
            payload_observation = if duplicate { Repeat } else {
                tcp_payload_observation(&slices.slices, payload_sequence, segment.payload)
            };
            let already_seen = matches!(payload_observation, Repeat);
            if segment.flags & RST == 0
                && let Some(reset) = state.reset
                && !state.post_reset_alerted[usize::from(reset.from_a != segment.from_a)]
                && reset.packet_no != pkt.no
                && observation_precedes((reset.timestamp, reset.packet_no), (pkt.timestamp, pkt.no))
                && (0.0..=TCP_STATE_TTL_SECS).contains(&(pkt.timestamp - reset.timestamp))
                && !already_seen
            {
                state.post_reset_alerted[usize::from(reset.from_a != segment.from_a)] = true;
                post_reset = Some(reset);
            }
            if !state.overlap_alerted
                && !duplicate
                && let Some(conflict) = conflicting_tcp_overlap(&slices.slices, payload_sequence, segment.payload)
            {
                state.overlap_alerted = true;
                overlap = Some(conflict);
            }
            if !already_seen {
                let remembered = slices.remember_distinct(pkt.no, payload_sequence, segment.payload);
                if remembered && !state.overlap_alerted && archive_rules.is_some() {
                    self.tcp_overlap_evidence.remember(pkt);
                }
            }
        }

        if in_time_order && segment.flags & (SYN | FIN | RST) == RST {
            state.reset = Some(TcpResetObservation {
                packet_no: pkt.no,
                timestamp: pkt.timestamp,
                sequence: segment.sequence,
                from_a: segment.from_a,
            });
            state.reset_evidence = (state.post_reset_alerted.contains(&false) && retain_reset()
                && crate::model::project::pinned_packet_cost(pkt) <= MAX_RESET_EVIDENCE_BYTES)
                .then(|| Box::new(pkt.clone()));
        }

        if let Some(reset) = post_reset {
            if retain_reset() {
                let evidence = if state.post_reset_alerted == [true, true] {
                    state.reset_evidence.take()
                } else {
                    state.reset_evidence.clone()
                };
                if let Some(packet) = evidence {
                    self.findings.retained_evidence.push(*packet);
                }
            }
            let (src, dst) = if segment.from_a {
                (segment.key.endpoint_a, segment.key.endpoint_b)
            } else {
                (segment.key.endpoint_b, segment.key.endpoint_a)
            };
            let (direction, severity, caveat) = if reset.from_a == segment.from_a {
                ("same", Severity::Medium, "")
            } else {
                ("opposite", Severity::Low, "; peer payload may already have been in flight")
            };
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: "TCP payload after reset",
                    severity,
                    detail: format!(
                        "TCP {} to {}: payload seq {} followed reset frame #{} ({} direction, seq {}); reset acceptance and on-wire ordering unverified{caveat}",
                        src, dst,
                        segment.sequence, reset.packet_no, direction, reset.sequence,
                    ),
                },
                related_packets: vec![reset.packet_no],
                correlation_key: Some(format!("{scope:?}:{:?}:reset:{}", segment.key, reset.packet_no)),
            });
        }
        if let Some(conflict) = overlap {
            if archive_rules.is_some()
                && let Some(prior) = self.tcp_overlap_evidence.cited_packet(pkt, conflict.previous_frame)
            {
                self.findings.retained_evidence.push(prior.clone());
            }
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
        payload_observation
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/security_fragment_state_tests.rs"]
mod tests;
