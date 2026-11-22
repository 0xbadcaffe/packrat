//! Versioned evidence descriptions for selected built-in detection rules.

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
            "ARP", "ARP binding changed", "arp.reply_binding_change", 2, Correlated,
            "Compare both ARP replies with DHCP leases, failover events, and the affected host's neighbor table.",
        ),
        (
            "IDS", "Periodic fixed-size traffic", "traffic.periodic_fixed_size", 1, Heuristic,
            "Identify the owning process and expected interval before escalating.",
        ),
        (
            "IDS", "Horizontal host scan", "scan.horizontal", 3, Heuristic,
            "Compare destinations and completed handshakes; check expected discovery or monitoring.",
        ),
        (
            "IDS", "Vertical port scan", "scan.vertical", 3, Heuristic,
            "Compare destination ports and completed handshakes; check scheduled scanning.",
        ),
        (
            "IDS", "SYN arrival spike", "tcp.syn_arrival_spike", 2, Correlated,
            "Check handshake completion, server reachability, and whether a burst was expected.",
        ),
        (
            "IDS", "TCP payload after reset", "tcp.payload_after_observed_reset", 2, Heuristic,
            "Compare the retained reset and payload frames with the flow, capture timing, and endpoint TCP logs.",
        ),
        (
            "IDS", "Conflicting IPv4 fragments", "ipv4.conflicting_fragments", 2, DirectObservation,
            "Compare both frames and their capture scope; check receiver logs for reassembly outcome.",
        ),
        (
            "IDS", "ICMP address sweep", "icmp.address_sweep", 1, Heuristic,
            "Check whether the echo requests match expected diagnostics or discovery.",
        ),
        (
            "IDS", "NTLM authentication fan-out", "smb2.ntlm_authentication_fanout", 1, Correlated,
            "Check whether the source normally contacts these hosts and corroborate with server logon events.",
        ),
        (
            "IDS", "SMBv1 server response", "smb1.successful_server_response", 1, DirectObservation,
            "Identify the server and legacy dependency; verify SMBv1 configuration and pilot removal before disabling it.",
        ),
        (
            "IDS", "NBNS WPAD address reply", "nbns.wpad_address_reply", 1, DirectObservation,
            "Check whether the responder is an approved proxy discovery service and whether the client used it.",
        ),
        (
            "IDS", "Administrative service response fan-out", "tcp.admin_service_response_fanout", 1, Correlated,
            "Inspect the retained SYN and SYN-ACK pairs; confirm completed sessions and expected management activity.",
        ),
        (
            "IDS", "Conflicting DNS responses", "dns.competing_responders", 3, Correlated,
            "Compare the query and both replies; verify which resolvers were authorized.",
        ),
        (
            "IDS", "DNS answer set changed at the same resolver", "dns.changed_answers", 3, Correlated,
            "Compare answer records and response codes; check expected resolver behavior.",
        ),
        (
            "IDS", "DNS reply changed at the same resolver", "dns.changed_wire_reply", 3, Heuristic,
            "Decode both replies before concluding that their answers differ.",
        ),
        (
            "IDS", "DNS transaction question mismatch", "dns.question_mismatch", 3, Correlated,
            "Compare the question name, type, and class in the query and reply.",
        ),
        (
            "IDS", "Unexpected DNS responder", "dns.unexpected_responder", 3, Correlated,
            "Check the configured resolver and whether a forwarding or failover path was expected.",
        ),
        (
            "IDS", "DNS reply without observed query", "dns.unmatched_response", 4, Heuristic,
            "Check capture start, packet drops, query-direction visibility, and the DNS correlation window.",
        ),
        (
            "IDS", "DNS reply correlation ambiguous", "dns.ambiguous_reply", 1, Heuristic,
            "Compare concurrent DNS queries on the same client port and transaction ID before assigning the reply.",
        ),
        (
            "IDS", "DNS NXDOMAIN burst", "dns.nxdomain_distinct_names", 1, Correlated,
            "Review the queried names and client process; search suffixes and misconfiguration can also cause bursts.",
        ),
        (
            "IDS", "Oversized DNS TXT traffic", "dns.large_txt_answer", 1, Correlated,
            "Check the queried name and record contents; verification records and mail policy can produce large TXT replies.",
        ),
        (
            "IDS", "Direct external DNS resolver use", "dns.external_resolver_exchange", 1, Correlated,
            "Check the configured resolver policy, including approved public resolvers, VPNs and lab address ranges.",
        ),
        (
            "AUTH", "HTTP authentication burst", "http.unauthorized_burst", 2, DirectObservation,
            "Compare the distinct 401 responses with application logs; check expected challenges.",
        ),
        (
            "AUTH", "SSH connection-start burst", "ssh.connection_start_burst", 1, DirectObservation,
            "Check handshake completion and compare with SSH server logs for authentication outcomes.",
        ),
        (
            "AUTH", "FTP not-logged-in reply burst", "ftp.not_logged_in_burst", 1, DirectObservation,
            "Inspect the preceding FTP commands and server logs; a 530 reply can reject a non-login command.",
        ),
        (
            "AUTH", "SMB2 logon failure burst", "smb2.logon_failure_burst", 1, DirectObservation,
            "Compare session setup replies with Windows logon events; check for stale credentials or scheduled jobs.",
        ),
    ]
};

pub(super) fn lookup(source: &str, title: &str) -> Option<AlertProvenance> {
    RULES
        .iter()
        .find(|&&(namespace, signature, ..)| namespace == source && signature == title)
        .map(|&(_, _, rule_id, revision, confidence, hint)| AlertProvenance {
            rule_id: rule_id.into(),
            revision,
            confidence,
            verification_hint: hint.into(),
        })
}

pub fn is_registered_rule_id(id: &str) -> bool {
    RULES.iter().any(|&(_, _, rule_id, ..)| rule_id == id)
}
