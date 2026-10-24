use super::*;

impl SecurityEngine {
    pub fn new() -> Self {
        Self {
            findings: DetectionBatch::default(),
            ids_alerts: Vec::new(),
            arp_anomalies: Vec::new(),
            os_guesses: Vec::new(),
            vuln_hits: Vec::new(),
            brute_force: Vec::new(),
            http_records: Vec::new(),
            tls_weaknesses: Vec::new(),
            dns_suspects: Vec::new(),
            ip_to_mac: HashMap::new(),
            os_by_ip: HashMap::new(),
            bf_windows: HashMap::new(),
            dns_accum: HashMap::new(),
            fragment_states: HashMap::new(),
            tcp_integrity: HashMap::new(),
            scan_sources: HashMap::new(),
            syn_flood_targets: HashMap::new(),
            ndp_bindings: HashMap::new(),
            router_advertisements: HashMap::new(),
            lldp_chassis: HashMap::new(),
            beacon_flows: HashMap::new(),
            exfil_flows: HashMap::new(),
            nxdomain_clients: HashMap::new(),
            external_dns_pairs: HashMap::new(),
            admin_fanout: HashMap::new(),
            ntlm_fanout: HashMap::new(),
            dhcp_vlans: HashMap::new(),
            ipv6_fragments: Ipv6FragmentReassembler::default(),
            ipv6_reassembled: 0,
            http_headers: HashMap::new(),
            dns_transactions: DnsTransactionTracker::default(),
            cred_hit_count: 0,
        }
    }

    pub fn clear(&mut self) {
        self.findings = DetectionBatch::default();
        self.ids_alerts.clear();
        self.arp_anomalies.clear();
        self.os_guesses.clear();
        self.vuln_hits.clear();
        self.brute_force.clear();
        self.http_records.clear();
        self.tls_weaknesses.clear();
        self.dns_suspects.clear();
        self.ip_to_mac.clear();
        self.os_by_ip.clear();
        self.bf_windows.clear();
        self.dns_accum.clear();
        self.fragment_states.clear();
        self.tcp_integrity.clear();
        self.scan_sources.clear();
        self.syn_flood_targets.clear();
        self.ndp_bindings.clear();
        self.router_advertisements.clear();
        self.lldp_chassis.clear();
        self.beacon_flows.clear();
        self.exfil_flows.clear();
        self.nxdomain_clients.clear();
        self.external_dns_pairs.clear();
        self.admin_fanout.clear();
        self.ntlm_fanout.clear();
        self.dhcp_vlans.clear();
        self.ipv6_fragments.clear();
        self.ipv6_reassembled = 0;
        self.http_headers.clear();
        self.dns_transactions.clear();
        self.cred_hit_count = 0;
    }

    /// Look up the OS guess for a given IP (if fingerprinted).
    pub fn os_guess_for(&self, ip: &str) -> Option<&'static str> {
        self.os_by_ip.get(ip).copied()
    }

    pub fn alert_count(&self) -> usize {
        self.ids_alerts.len()
            + self.arp_anomalies.len()
            + self.vuln_hits.len()
            + self.brute_force.len()
            + self.tls_weaknesses.len()
    }

    pub fn summary(&self) -> SecuritySummary {
        // Count flagged DNS suspects (score > 8)
        let dns_suspects = self.dns_suspects.iter().filter(|d| d.score > 8.0).count();
        SecuritySummary {
            ids_alerts: self.ids_alerts.len(),
            arp_anomalies: self.arp_anomalies.len(),
            os_guesses: self.os_by_ip.len(),
            vuln_hits: self.vuln_hits.len(),
            brute_force: self.brute_force.len(),
            http_records: self.http_records.len(),
            tls_weaknesses: self.tls_weaknesses.len(),
            dns_suspects,
            cred_hits: self.cred_hit_count,
            ipv6_reassembled: self.ipv6_reassembled,
        }
    }

    /// Process a single packet through all detection engines.
    pub fn update(&mut self, pkt: &Packet) {
        self.findings = DetectionBatch::default();
        self.check_ipv4_fragments(pkt);
        self.check_tcp_integrity(pkt);
        self.check_scan_activity(pkt);
        self.check_ipv6_control_plane(pkt);
        self.check_layer2_control_plane(pkt);
        self.check_beacon_and_exfiltration(pkt);
        self.check_dns_abuse_and_lateral_movement(pkt);
        self.check_dhcp_integrity(pkt);
        self.check_ipv6_fragment_reassembly(pkt);
        self.check_http_request_smuggling(pkt);
        self.check_industrial_policy(pkt);
        self.check_dns_transaction_integrity(pkt);
        self.check_ids(pkt);
        self.check_arp(pkt);
        self.check_os_fingerprint(pkt);
        self.check_vuln(pkt);
        self.check_brute_force(pkt);
        self.check_http(pkt);
        self.check_tls(pkt);
        self.check_dns_tunnel(pkt);
    }

    pub fn inspect(&mut self, pkt: &Packet) -> DetectionBatch {
        self.update(pkt);
        std::mem::take(&mut self.findings)
    }

    // ─── IDS Signatures ──────────────────────────────────────────────────────

    pub(super) fn push_ids(&mut self, alert: IdsAlert) {
        self.findings.ids.push(alert.clone());
        debug_assert!(
            DETECTOR_SIGNATURES.contains(&alert.signature),
            "detector signature lacks replay coverage registration: {}",
            alert.signature
        );
        if self.ids_alerts.len() >= MAX_ENTRIES {
            self.ids_alerts.remove(0);
        }
        self.ids_alerts.push(alert);
    }
}
