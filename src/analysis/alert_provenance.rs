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
            "IDS", "Periodic fixed-size traffic", "traffic.periodic_fixed_size", 1, Heuristic,
            "Identify the owning process and expected interval before escalating.",
        ),
        (
            "IDS", "Horizontal host scan", "scan.horizontal", 2, Heuristic,
            "Compare destinations and completed handshakes; check expected discovery or monitoring.",
        ),
        (
            "IDS", "Vertical port scan", "scan.vertical", 2, Heuristic,
            "Compare destination ports and completed handshakes; check scheduled scanning.",
        ),
        (
            "IDS", "SYN arrival spike", "tcp.syn_arrival_spike", 1, Correlated,
            "Check handshake completion, server reachability, and whether a burst was expected.",
        ),
        (
            "IDS", "Conflicting DNS responses", "dns.competing_responders", 1, Correlated,
            "Compare the query and both replies; verify which resolvers were authorized.",
        ),
        (
            "IDS", "DNS answer set changed at the same resolver", "dns.changed_answers", 1, Correlated,
            "Compare answer records and response codes; check expected resolver behavior.",
        ),
        (
            "IDS", "DNS reply changed at the same resolver", "dns.changed_wire_reply", 1, Heuristic,
            "Decode both replies before concluding that their answers differ.",
        ),
        (
            "IDS", "DNS transaction question mismatch", "dns.question_mismatch", 1, Correlated,
            "Compare the question name, type, and class in the query and reply.",
        ),
        (
            "IDS", "Unexpected DNS responder", "dns.unexpected_responder", 1, Correlated,
            "Check the configured resolver and whether a forwarding or failover path was expected.",
        ),
        (
            "IDS", "Unsolicited DNS response", "dns.unmatched_response", 1, Heuristic,
            "Check capture start, packet drops, and visibility of the query direction.",
        ),
        (
            "AUTH", "HTTP authentication burst", "http.unauthorized_burst", 1, DirectObservation,
            "Compare the distinct 401 responses with application logs; check expected challenges.",
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
