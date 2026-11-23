use super::*;

impl SecurityEngine {
    pub(super) fn record_echo_request(&mut self, pkt: &Packet, protocol: &'static str, retain: bool) {
        let key = scan_key(pkt, protocol);
        let state = self.scan_state(key.clone());
        let change = state.push_probe(pkt, 0, None);
        let count = state.probes.len();
        let finding = if matches!(change, ProbeChange::Distinct) && count >= SCAN_UNIQUE_THRESHOLD && !state.icmp_alerted {
            state.icmp_alerted = true;
            let mut finding = scan_finding(
                pkt, &key, "ICMP address sweep", "echo",
                format!("{} probed {count} hosts with {protocol} echo requests", pkt.src),
                state.probes.iter(),
            );
            finding.alert.severity = Severity::Medium;
            Some(finding)
        } else {
            None
        };
        if retain {
            if let Some(finding) = &finding {
                self.findings.retained_evidence.extend(finding.related_packets.iter().filter_map(|&frame| {
                    self.echo_sweep_evidence.cited_packet(pkt, frame).cloned()
                }));
            }
            if !matches!(change, ProbeChange::Ignored) { self.echo_sweep_evidence.remember(pkt); }
        }
        if let Some(finding) = finding { self.push_ids_finding(finding); }
    }
}
