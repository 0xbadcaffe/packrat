use super::*;
use crate::analysis::stream::HttpAuthObservation;

impl SecurityEngine {
    pub(crate) fn observe_saved_dns_context(&mut self, packet: &Packet, tcp: &crate::analysis::stream::DnsTcpObservation) {
        let _ = self.dns_transactions.observe_stream(packet, tcp);
    }

    pub fn dns_exchange_for_packet(&self, packet: &Packet) -> Option<crate::analysis::dns_transactions::DnsExchangeEvidence> {
        self.dns_transactions.exchange_for_packet(packet)
    }

    pub fn dns_exchanges_for_packet(&self, packet: &Packet) -> Vec<crate::analysis::dns_transactions::DnsExchangeEvidence> {
        self.dns_transactions.exchanges_for_packet(packet)
    }

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
            dns_tunnel: Default::default(),
            fragment_states: HashMap::new(),
            tcp_integrity: HashMap::new(),
            scan_sources: HashMap::new(),
            syn_flood_targets: HashMap::new(),
            ndp_bindings: HashMap::new(),
            router_advertisements: HashMap::new(),
            router_rate_evidence: Default::default(),
            default_router_links: HashMap::new(),
            lldp_chassis: HashMap::new(),
            beacon_flows: HashMap::new(),
            exfil_flows: HashMap::new(),
            admin_fanout: Default::default(),
            ftp_control: Default::default(),
            ntlm_fanout: HashMap::new(),
            dhcp_scopes: HashMap::new(),
            dhcp_server_evidence: Default::default(),
            ipv6_fragments: Ipv6FragmentReassembler::default(),
            ipv6_reassembled: 0,
            http_headers: HashMap::new(),
            dns_transactions: DnsTransactionTracker::default(),
            dns_packet_evidence: Default::default(),
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
        self.dns_tunnel.clear();
        self.fragment_states.clear();
        self.tcp_integrity.clear();
        self.scan_sources.clear();
        self.syn_flood_targets.clear();
        self.ndp_bindings.clear();
        self.router_advertisements.clear();
        self.router_rate_evidence = Default::default();
        self.default_router_links.clear();
        self.lldp_chassis.clear();
        self.beacon_flows.clear();
        self.exfil_flows.clear();
        self.admin_fanout.clear();
        self.ftp_control.clear();
        self.ntlm_fanout.clear();
        self.dhcp_scopes.clear();
        self.dhcp_server_evidence = Default::default();
        self.ipv6_fragments.clear();
        self.ipv6_reassembled = 0;
        self.http_headers.clear();
        self.dns_transactions.clear();
        self.dns_packet_evidence = Default::default();
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
        self.update_with_context(pkt, industrial_policy::ModbusObservation::Unanchored, None,
            crate::analysis::stream::DnsTcpObservation::Unanchored, HttpAuthObservation::Packet, None);
    }

    fn update_with_context(&mut self, pkt: &Packet, modbus: industrial_policy::ModbusObservation,
        tls: Option<(u16, u16)>, dns: crate::analysis::stream::DnsTcpObservation,
        http_auth: HttpAuthObservation, archive_rules: Option<&[String]>,
    ) {
        self.findings = DetectionBatch::default();
        if pkt.capture.as_ref().is_some_and(|capture| !crate::net::parser::supports_capture_link_type(capture.link_type))
            || (crate::net::parser::is_vlan_ether_type(u16_be_at(&pkt.bytes, 12))
                && ethernet_network_header(&pkt.bytes).is_none())
        {
            return;
        }
        self.check_ipv4_fragments(pkt);
        let tcp_payload = self.check_tcp_integrity(pkt, archive_rules);
        self.check_scan_activity(pkt);
        self.check_ipv6_control_plane(pkt, archive_rules);
        self.check_layer2_control_plane(pkt);
        self.check_beacon_and_exfiltration(pkt, tcp_payload, archive_rules);
        self.check_ntlm_fanout(pkt);
        self.check_dhcp_integrity(pkt, archive_rules);
        self.check_ipv6_fragment_reassembly(pkt);
        self.check_http_request_smuggling(pkt);
        self.check_industrial_policy(pkt, modbus);
        self.check_dns_transaction_integrity(pkt, &dns, archive_rules);
        self.check_ids(pkt);
        self.check_arp(pkt);
        self.check_os_fingerprint(pkt);
        self.check_vuln(pkt);
        self.check_ftp_control(pkt);
        self.check_brute_force(pkt, http_auth);
        self.check_http(pkt);
        self.check_tls(pkt, tls);
        self.check_dns_tunnel(pkt, &dns);
    }

    pub fn inspect(&mut self, pkt: &Packet) -> DetectionBatch {
        self.inspect_with_context(pkt, industrial_policy::ModbusObservation::Unanchored, None,
            crate::analysis::stream::DnsTcpObservation::Unanchored, HttpAuthObservation::Packet, None)
    }

    pub(crate) fn inspect_with_context(
        &mut self, pkt: &Packet, modbus: industrial_policy::ModbusObservation, tls: Option<(u16, u16)>,
        dns: crate::analysis::stream::DnsTcpObservation, http_auth: HttpAuthObservation,
        archive_rules: Option<&[String]>,
    ) -> DetectionBatch {
        self.update_with_context(pkt, modbus, tls, dns, http_auth, archive_rules);
        std::mem::take(&mut self.findings)
    }

    // ─── IDS Signatures ──────────────────────────────────────────────────────

    pub(super) fn push_ids(&mut self, alert: IdsAlert) {
        self.push_ids_with_evidence(alert, Vec::new());
    }

    pub(super) fn push_ids_with_evidence(&mut self, alert: IdsAlert, related_packets: Vec<u64>) {
        self.push_ids_finding(IdsFinding {
            alert,
            related_packets,
            correlation_key: None,
        });
    }

    pub(super) fn push_ids_finding(&mut self, finding: IdsFinding) {
        let alert = &finding.alert;
        debug_assert!(
            DETECTOR_SIGNATURES.contains(&alert.signature),
            "detector signature lacks replay coverage registration: {}",
            alert.signature
        );
        if self.ids_alerts.len() >= MAX_ENTRIES {
            self.ids_alerts.remove(0);
        }
        self.ids_alerts.push(alert.clone());
        self.findings.ids.push(finding);
    }
}
