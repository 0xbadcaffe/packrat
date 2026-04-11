//! Typed references linking any analysis finding back to its source evidence.

use std::fmt;

// ─── Source references ────────────────────────────────────────────────────────

/// Reference to a single captured packet by frame number.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct PacketRef(pub u64);

/// Reference to a bidirectional flow (src_ip:port ↔ dst_ip:port).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FlowRef(pub String); // "{ep1}-{ep2}-{proto}"

/// Reference to a network host by IP.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct HostRef(pub String); // IP string

/// Reference to a reassembled stream.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct StreamRef(pub FlowRef);

/// Reference to a carved/extracted object.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ObjectRef(pub u64); // sequential ID

/// A general evidence pointer — any of the above source types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum EvidenceRef {
    Packet(PacketRef),
    Flow(FlowRef),
    Host(HostRef),
    Stream(StreamRef),
    Object(ObjectRef),
}

impl fmt::Display for EvidenceRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvidenceRef::Packet(r)  => write!(f, "pkt#{}", r.0),
            EvidenceRef::Flow(r)    => write!(f, "flow:{}", r.0),
            EvidenceRef::Host(r)    => write!(f, "host:{}", r.0),
            EvidenceRef::Stream(r)  => write!(f, "stream:{}", (r.0).0),
            EvidenceRef::Object(r)  => write!(f, "obj#{}", r.0),
        }
    }
}

// ─── Severity / confidence ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info     => write!(f, "INFO"),
            Severity::Low      => write!(f, "LOW"),
            Severity::Medium   => write!(f, "MEDIUM"),
            Severity::High     => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Confidence { Low, Medium, High, Certain }

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Confidence::Low    => write!(f, "low"),
            Confidence::Medium => write!(f, "medium"),
            Confidence::High   => write!(f, "high"),
            Confidence::Certain=> write!(f, "certain"),
        }
    }
}

// ─── Finding — generic alert/match result ────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub source:     EvidenceRef,
    pub kind:       String,
    pub severity:   Severity,
    pub confidence: Confidence,
    pub summary:    String,
    pub detail:     Option<String>,
    pub timestamp:  f64,
}

impl Finding {
    pub fn new(
        source: EvidenceRef,
        kind: impl Into<String>,
        severity: Severity,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            source,
            kind: kind.into(),
            severity,
            confidence: Confidence::Medium,
            summary: summary.into(),
            detail: None,
            timestamp: current_ts(),
        }
    }
}

fn current_ts() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
