//! Versioned evidence descriptions for built-in detection rules.

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceConfidence {
    Heuristic,
    Correlated,
    DirectObservation,
}

impl std::fmt::Display for EvidenceConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Heuristic => "Heuristic",
            Self::Correlated => "Correlated",
            Self::DirectObservation => "Direct observation",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AlertProvenance {
    pub rule_id: String,
    pub revision: u16,
    pub confidence: EvidenceConfidence,
    pub verification_hint: String,
}

impl AlertProvenance {
    pub fn rule_label(&self) -> String {
        format!("{} r{}", self.rule_id, self.revision)
    }
}

type RuleDefinition = (
    &'static str,
    &'static str,
    &'static str,
    u16,
    EvidenceConfidence,
    &'static str,
);

pub(super) const RULES: &[RuleDefinition] = {
    use EvidenceConfidence::{Correlated, DirectObservation, Heuristic};
    &[
        (
            "IDS", "Malformed IPv4 fragment", "ipv4.fragment_invalid_length", 1, DirectObservation,
            "Compare the IPv4 header and declared length with the retained frame and capture metadata. Check whether the receiving stack discarded it.",
        ),
        (
            "IDS", "Tiny IPv4 fragment", "ipv4.fragment_small_payload", 1, DirectObservation,
            "Inspect the fragment flags, offset, payload length, and other frames for the datagram; size alone does not establish intent.",
        ),
        (
            "IDS", "IPv4 fragment flood", "ipv4.fragment_observation_burst", 2, Correlated,
            "Inspect the retained fragment offsets and compare with link MTU, source behavior, and endpoint resource pressure. Volume alone does not establish denial of service.",
        ),
        (
            "IDS", "Malformed TCP header", "tcp.invalid_header", 4, DirectObservation,
            "Check the TCP header length against the captured and declared IP lengths. Confirm truncation and endpoint handling independently.",
        ),
        (
            "IDS", "Illegal TCP flag combination", "tcp.inconsistent_flags", 1, DirectObservation,
            "Verify the flag bits in the retained segment and compare nearby flow traffic. The flags alone do not establish why the segment was sent.",
        ),
        (
            "IDS", "TCP stealth scan probe", "tcp.unusual_probe_flags", 2, Heuristic,
            "Compare nearby attempts and replies with expected application behavior before diagnosing a scan.",
        ),
        (
            "IDS", "Excessive IPv6 extension headers", "ipv6.long_extension_chain", 1, DirectObservation,
            "Inspect the extension chain, capture length, and local link policy. A long chain does not establish forwarding impact.",
        ),
        (
            "IDS", "IPv6 fragment reassembly rejected", "ipv6.reassembly_rejected", 1, DirectObservation,
            "Check the stated local reassembly rejection and related fragments. Confirm endpoint handling separately.",
        ),
        (
            "IDS", "HTTP request smuggling ambiguity", "http.request_framing_ambiguity", 1, Heuristic,
            "Compare retained headers with the full stream and with proxy and server logs. The finding does not establish divergent parsing or compromise.",
        ),
        (
            "IDS", "Directory Traversal", "payload.path_traversal_marker", 1, Heuristic,
            "Locate the byte pattern in the reconstructed application message and check server access logs before inferring a traversal attempt.",
        ),
        (
            "IDS", "SQL Injection Probe", "payload.sql_like_marker", 1, Heuristic,
            "Verify the match in application context and compare with server logs. Text alone does not establish a database query or execution.",
        ),
        (
            "IDS", "XSS Probe", "payload.script_like_marker", 1, Heuristic,
            "Verify whether the matched text was user input and how the application handled it. The match does not establish browser execution.",
        ),
        (
            "IDS", "Heartbleed (CVE-2014-0160)", "tls.legacy_heartbeat_pattern", 1, Heuristic,
            "Verify message framing and the endpoint's patch status. The byte pattern does not establish a TLS heartbeat or information disclosure.",
        ),
        (
            "IDS", "Repeated NOP-like byte pattern", "payload.nop_like_byte_run", 1, Heuristic,
            "Inspect the retained transport payload and expected application format; a repeated byte alone does not identify executable content.",
        ),
        (
            "ARP", "ARP binding changed", "arp.reply_binding_change", 3, Correlated,
            "Compare both ARP replies with DHCP leases, failover events, and the affected host's neighbor table.",
        ),
        (
            "ARP", "ARP announcement binding changed", "arp.announcement_binding_change", 2, Correlated,
            "Compare the claims with address assignments, failover logs, and endpoint neighbor tables. An announcement does not prove cache poisoning.",
        ),
        (
            "IDS", "ARP reply sender differs from Ethernet source", "arp.reply_source_mismatch", 1, DirectObservation,
            "Compare the Ethernet source and ARP sender with switch and neighbor tables. Check for authorized address rewriting or gateway redundancy.",
        ),
        (
            "IDS", "Alternating ARP claims", "arp.alternating_claims", 3, Correlated,
            "Compare all three claims with switch learning, DHCP leases, and failover logs; check whether endpoint neighbor entries actually changed.",
        ),
        (
            "IDS", "Invalid IPv6 neighbor discovery hop limit", "ipv6.ndp_invalid_hop_limit", 1, DirectObservation,
            "Verify the IPv6 hop limit at the original link and check router configuration and endpoint logs; the observed packet does not prove a neighbor cache or route changed.",
        ),
        (
            "IDS", "Invalid IPv6 router advertisement source", "ipv6.ra_source_not_link_local", 1, DirectObservation,
            "Verify router interface configuration and check whether endpoints ignored the advertisement.",
        ),
        (
            "IDS", "IPv6 router advertisement flood", "ipv6.ra_rate_burst", 2, Correlated,
            "Compare the retained advertisements with the approved router inventory and verify endpoint router selection.",
        ),
        (
            "IDS", "IPv6 default router Ethernet source changed", "ipv6.ra_router_link_change", 2, Correlated,
            "Compare both advertisements with the switch-port inventory and planned router failover. Check endpoint default routes before attributing impact.",
        ),
        (
            "IDS", "DNS tunnel behavior", "dns.high_entropy_query_burst", 4, Heuristic,
            "Compare the retained queries with expected DNS clients and resolver logs; investigate the originating process before concluding that data was transferred.",
        ),
        (
            "IDS", "IPv6 neighbor binding changed", "ipv6.ndp_binding_change", 3, Correlated,
            "Compare both advertisements with the authorized address assignments and endpoint neighbor tables; distinguish failover from spoofing.",
        ),
        (
            "IDS", "STP topology change", "stp.topology_change_indication", 1, DirectObservation,
            "Compare the BPDU with switch topology and maintenance logs; the indication does not prove a forwarding change.",
        ),
        (
            "IDS", "LLDP chassis identity changed", "lldp.chassis_identity_change", 3, Correlated,
            "Compare both advertisements with the switch-port inventory and maintenance records before attributing the change.",
        ),
        (
            "VLAN", "MAC-VLAN-Cross", super::vlan::MAC_VLAN_CROSSING_RULE, 2, Correlated,
            "Compare the two frames with trunk, VLAN and switch-port policy. A shared MAC alone does not establish forwarding between VLANs.",
        ),
        (
            "VLAN", "DTP", "vlan.dtp_negotiation", 1, DirectObservation,
            "Check whether dynamic trunk negotiation is expected on this switch port. Confirm trunk state with switch logs before escalating.",
        ),
        (
            "VLAN", "Stacked VLAN tags", "vlan.tag_stack_observed", 1, DirectObservation,
            "Check both tags against the capture interface's trunk or provider tunnel policy. Tag stacking alone does not prove cross-VLAN forwarding.",
        ),
        (
            "VLAN", "Unexpected VLAN tag stack", "vlan.tag_stack_policy_violation", 1, DirectObservation,
            "Verify the capture-interface mapping and expected switch-port policy, then check switch logs before inferring forwarding.",
        ),
        (
            "VLAN", super::vlan::VLAN_ID_ONE, "vlan.vid_one_observed", 1, DirectObservation,
            "Read the switch port's configured native VLAN and allowed VLANs. A tagged VID 1 frame does not establish either setting.",
        ),
        (
            "VLAN", super::vlan::VLAN_PCP_SEVEN, "vlan.pcp_seven_observed", 1, DirectObservation,
            "Compare the marking with the port's QoS trust policy and switch counters before inferring priority misuse.",
        ),
        (
            "IDS", "Periodic fixed-size traffic", "traffic.periodic_fixed_size", 13, Heuristic,
            "Identify the owning process and compare the interval with expected keepalives or scheduled activity before escalating.",
        ),
        (
            "IDS", "Large asymmetric outbound transfer", "traffic.asymmetric_outbound", 8, Heuristic,
            "Identify the owning process and destination. Check for an expected upload, backup, or sync job.",
        ),
        (
            "IDS", "High-entropy outbound transfer", "traffic.high_entropy_outbound", 8, Heuristic,
            "Check whether the traffic is normally encrypted or compressed. Verify the transfer with endpoint logs.",
        ),
        (
            "IDS", "Horizontal host scan", "scan.horizontal", 14, Heuristic,
            "Compare targets and matched replies with expected discovery or monitoring. For TCP, look for completed handshakes; for UDP, check service logs.",
        ),
        (
            "IDS", "Vertical port scan", "scan.vertical", 14, Heuristic,
            "Compare destination ports and matched replies with scheduled scans. Look for completed TCP handshakes or corroborating UDP service logs.",
        ),
        (
            "IDS", "SYN arrival spike", "tcp.syn_arrival_spike", 7, Correlated,
            "Check handshake completion, server reachability, and whether a burst was expected.",
        ),
        (
            "IDS", "TCP payload after reset", "tcp.payload_after_observed_reset", 8, Heuristic,
            "Compare the retained reset and payload frames with the flow, capture timing, and endpoint TCP logs.",
        ),
        (
            "IDS", "Conflicting TCP retransmission", "tcp.conflicting_retransmission", 5, DirectObservation,
            "Compare both frames and their TCP sequence ranges. Check capture duplication or offload and verify what the receiver processed independently.",
        ),
        (
            "IDS", "Conflicting IPv4 fragments", "ipv4.conflicting_fragments", 2, DirectObservation,
            "Compare both frames and their capture scope; check receiver logs for reassembly outcome.",
        ),
        (
            "IDS", "Conflicting IPv6 fragments", "ipv6.conflicting_fragments", 2, DirectObservation,
            "Compare the overlapping bytes in both frames. Verify the receiver's handling independently; this alert does not show that the datagram was accepted.",
        ),
        (
            "IDS", "ICMP address sweep", "icmp.address_sweep", 5, Heuristic,
            "Check whether the echo requests match expected diagnostics or discovery.",
        ),
        (
            "IDS", "NTLM authentication fan-out", "smb2.ntlm_authentication_fanout", 3, Correlated,
            "Check whether the source normally contacts these hosts and corroborate with server logon events.",
        ),
        (
            "IDS", "DHCP client identity burst", "dhcp.discover_identity_burst", 4, Heuristic,
            "Compare the sampled client identities with expected reconnects and check DHCP server logs for lease pool exhaustion.",
        ),
        (
            "IDS", "DHCP server identity changed", "dhcp.new_server_identifier", 5, Correlated,
            "Compare the retained replies with the approved DHCP server inventory and check for planned failover or migration.",
        ),
        (
            "IDS", "SMBv1 server response", "smb1.successful_server_response", 1, DirectObservation,
            "Identify the server and legacy dependency; verify SMBv1 configuration and pilot removal before disabling it.",
        ),
        (
            "IDS", "SMB2 anonymous session accepted", "smb2.anonymous_session_accepted", 1, DirectObservation,
            "Verify the server's anonymous access policy and check subsequent TREE_CONNECT responses or server share audit logs.",
        ),
        (
            "IDS", "Cleartext HTTP Basic authorization", "http.cleartext_basic_authorization", 1, DirectObservation,
            "Verify where TLS terminates, review who could read the captured traffic, and rotate exposed credentials as appropriate.",
        ),
        (
            "IDS", "Anonymous FTP login accepted", "ftp.anonymous_login_accepted", 1, Correlated,
            "Verify the anonymous FTP policy and review server logs for file listings, reads, or writes.",
        ),
        (
            "EXPOSURE", "Telnet authentication prompt", "telnet.authentication_prompt", 1, Heuristic,
            "Verify whether Telnet is expected and migrate remote administration to SSH; the prompt alone does not establish credential transmission.",
        ),
        (
            "TLS", "SSL 3.0 selected", "tls.ssl30_selected", 3, DirectObservation,
            "Verify the server's minimum protocol version and identify the client or intermediary requiring SSL 3.0.",
        ),
        (
            "TLS", "TLS 1.0 selected", "tls.tls10_selected", 3, DirectObservation,
            "Verify the server or proxy's minimum protocol version and check which clients still require TLS 1.0.",
        ),
        (
            "TLS", "TLS 1.1 selected", "tls.tls11_selected", 3, DirectObservation,
            "Verify the server or proxy's minimum protocol version and check which clients still require TLS 1.1.",
        ),
        (
            "TLS", "RC4 selected", "tls.rc4_selected", 4, DirectObservation,
            "Verify the selected cipher in ServerHello and remove RC4 from the server or proxy's allowed cipher suites.",
        ),
        (
            "IDS", "NBNS WPAD address reply", "nbns.wpad_address_reply", 1, DirectObservation,
            "Check whether the responder is an approved proxy discovery service and whether the client used it.",
        ),
        (
            "IDS", "Critical industrial control command", "industrial.critical_control", 5, Heuristic,
            "Verify the command and response against controller logs and approved maintenance. This packet does not prove execution.",
        ),
        (
            "IDS", "Industrial state-changing command", "industrial.state_change", 8, Heuristic,
            "Check the controller, operator authorization, and response. A write-like packet does not prove a state change.",
        ),
        (
            "IDS", "Administrative service response fan-out", "tcp.admin_service_response_fanout", 3, Correlated,
            "Inspect the retained SYN and SYN-ACK pairs; confirm completed sessions and expected management activity.",
        ),
        (
            "IDS", "Conflicting DNS responses", "dns.competing_responders", 7, Correlated,
            "Compare the query and both replies; verify which resolvers were authorized.",
        ),
        (
            "IDS", "DNS answer set changed at the same resolver", "dns.changed_answers", 11, Correlated,
            "Compare answer records and response codes; check expected resolver behavior.",
        ),
        (
            "IDS", "DNS reply changed at the same resolver", "dns.changed_wire_reply", 11, Heuristic,
            "Decode both replies before concluding that their answers differ.",
        ),
        (
            "IDS", "DNS transaction question mismatch", "dns.question_mismatch", 7, Correlated,
            "Compare the question name, type, and class in the query and reply.",
        ),
        (
            "IDS", "Unexpected DNS responder", "dns.unexpected_responder", 5, Correlated,
            "Check the configured resolver and whether a forwarding or failover path was expected.",
        ),
        (
            "IDS", "DNS reply without observed query", "dns.unmatched_response", 5, Heuristic,
            "Check capture start, packet drops, query-direction visibility, and the DNS correlation window.",
        ),
        (
            "IDS", "DNS reply correlation ambiguous", "dns.ambiguous_reply", 2, Heuristic,
            "Compare concurrent DNS queries on the same client port and transaction ID before assigning the reply.",
        ),
        (
            "IDS", "DNS invalid question count", "dns.invalid_question_count", 1, DirectObservation,
            "Inspect the captured DNS opcode and question count. Check resolver logs for a format error; this does not establish compromise.",
        ),
        (
            "IDS", "DNS NXDOMAIN burst", "dns.nxdomain_distinct_names", 4, Correlated,
            "Review the queried names and client process; search suffixes and misconfiguration can also cause bursts.",
        ),
        (
            "IDS", "Oversized DNS TXT traffic", "dns.large_txt_answer", 2, Correlated,
            "Check the queried name and record contents; verification records and mail policy can produce large TXT replies.",
        ),
        (
            "IDS", "Direct external DNS resolver use", "dns.external_resolver_exchange", 2, Correlated,
            "Check the configured resolver policy, including approved public resolvers, VPNs and lab address ranges.",
        ),
        (
            "IDS", "JNDI label in DNS query", "dns.jndi_question_label", 2, Heuristic,
            "Check the queried name against approved domains or threat intelligence. Identify the originating process before escalating.",
        ),
        (
            "IDS", "Log4Shell (CVE-2021-44228)", "log4j.literal_lookup_marker", 2, Heuristic,
            "Check whether the receiving application uses an affected library. Corroborate with application and outbound connection logs before escalating.",
        ),
        (
            "AUTH", "HTTP authentication burst", "http.unauthorized_burst", 16, DirectObservation,
            "Compare the distinct 401 responses with application logs; check expected challenges.",
        ),
        (
            "AUTH", "SSH connection-start burst", "ssh.connection_start_burst", 5, DirectObservation,
            "Check handshake completion and compare with SSH server logs for authentication outcomes.",
        ),
        (
            "AUTH", "FTP not-logged-in reply burst", "ftp.not_logged_in_burst", 6, DirectObservation,
            "Inspect the preceding FTP commands and server logs; a 530 reply can reject a non-login command.",
        ),
        (
            "AUTH", "SMB2 logon failure burst", "smb2.logon_failure_burst", 6, DirectObservation,
            "Compare session setup replies with Windows logon events; check for stale credentials or scheduled jobs.",
        ),
    ]
};

fn matching_rule(source: &str, title: &str) -> Option<&'static RuleDefinition> {
    RULES
        .iter()
        .find(|&&(namespace, signature, ..)| namespace == source && signature == title)
}

pub(crate) fn rule_id_for(source: &str, title: &str) -> Option<&'static str> {
    matching_rule(source, title).map(|rule| rule.2)
}

pub(super) fn lookup(source: &str, title: &str) -> Option<AlertProvenance> {
    matching_rule(source, title)
        .map(|&(_, _, rule_id, revision, confidence, hint)| AlertProvenance {
            rule_id: rule_id.into(),
            revision,
            confidence,
            verification_hint: hint.into(),
        })
}

pub fn is_registered_rule_id(id: &str) -> bool {
    registered_rule_revision(id).is_some()
}

pub(crate) fn registered_rule_revision(id: &str) -> Option<u16> {
    RULES.iter().find_map(|&(_, _, rule_id, revision, ..)| (rule_id == id).then_some(revision))
}
