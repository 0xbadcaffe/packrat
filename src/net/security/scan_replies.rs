use super::*;

const MAX_LINKED_PROBES: usize = 64;

impl SourceScanState {
    pub(super) fn retain_linked_probe(&mut self, probe: ScanProbe) {
        if !probe.linked_to_alert() {
            self.pending_final_acks -= usize::from(probe.awaits_final_ack());
            return;
        }
        if self.linked_probes.len() == MAX_LINKED_PROBES
            && let Some(oldest) = self.linked_probes.pop_front()
        {
            self.pending_final_acks -= usize::from(oldest.awaits_final_ack());
        }
        // Keep these separately so late replies cannot affect the distinct-target counts.
        self.linked_probes.push_back(probe);
    }
}

impl SecurityEngine {
    pub(super) fn record_scan_reply(&mut self, pkt: &Packet, tcp: TcpSignal, reset: bool) {
        let key = ScanSourceKey {
            address: pkt.dst.clone(),
            transport: "TCP",
            scope: service_scope(pkt),
        };
        let Some(state) = self.scan_sources.get_mut(&key) else { return };
        let Some(probe) = state.probes.iter_mut().chain(&mut state.linked_probes).find(|probe| {
            probe.destination == pkt.src && probe.port == tcp.source_port
                && (pkt.timestamp, pkt.no) > (probe.timestamp, probe.packet_no)
                && pkt.timestamp - probe.timestamp <= SCAN_WINDOW_SECS
                && probe.tcp.as_ref().is_some_and(|attempt| {
                    attempt.source_port == tcp.destination_port
                        && attempt.sequence.wrapping_add(1) == tcp.acknowledgement
                })
        }) else { return };
        let Some(attempt) = &mut probe.tcp else { return };
        let was_pending = attempt.awaits_final_ack();
        let newly_matched = if reset {
            let new = attempt.reset_ack.is_none();
            attempt.reset_ack.get_or_insert(pkt.no);
            new
        } else {
            let new = attempt.syn_ack.is_none();
            attempt.syn_ack.get_or_insert(ScanSynAck {
                order: (pkt.timestamp, pkt.no), sequence: tcp.sequence,
            });
            new
        };
        state.pending_final_acks += usize::from(attempt.awaits_final_ack());
        state.pending_final_acks -= usize::from(was_pending);
        if newly_matched {
            self.findings.ids_evidence.extend(probe.reply_evidence(pkt.no));
        }
    }

    pub(super) fn record_scan_final_ack(&mut self, pkt: &Packet, tcp: TcpSignal) {
        let Some(state) = self.scan_sources.get_mut(&scan_key(pkt, "TCP")) else { return };
        if state.pending_final_acks == 0 {
            return;
        }
        let Some(probe) = state.probes.iter_mut().chain(&mut state.linked_probes).find(|probe| {
            probe.destination == pkt.dst && probe.port == tcp.destination_port
                && pkt.timestamp - probe.timestamp <= SCAN_WINDOW_SECS
                && probe.tcp.as_ref().is_some_and(|attempt| {
                    attempt.source_port == tcp.source_port && attempt.awaits_final_ack()
                        && tcp.sequence == attempt.sequence.wrapping_add(1)
                        && attempt.syn_ack.as_ref().is_some_and(|reply| {
                            (pkt.timestamp, pkt.no) > reply.order
                                && tcp.acknowledgement == reply.sequence.wrapping_add(1)
                        })
                })
        }) else { return };
        let Some(attempt) = &mut probe.tcp else { return };
        attempt.final_ack = Some(pkt.no);
        state.pending_final_acks -= 1;
        self.findings.ids_evidence.extend(probe.reply_evidence(pkt.no));
    }
}
