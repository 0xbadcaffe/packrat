use super::{ArpAnomaly, BruteForceAlert, IdsAlert, TlsWeakness, VulnHit};

/// Findings emitted by one inspection, independent of retained history limits.
#[derive(Debug, Default)]
pub struct DetectionBatch {
    pub ids: Vec<IdsFinding>,
    pub arp: Vec<ArpFinding>,
    pub vulnerabilities: Vec<VulnHit>,
    pub authentication: Vec<BruteForceAlert>,
    pub tls: Vec<TlsWeakness>,
    pub(crate) ids_evidence: Vec<IdsEvidenceUpdate>,
    pub(crate) retained_evidence: Vec<crate::net::packet::Packet>,
}

#[derive(Debug)]
pub(crate) struct IdsEvidenceUpdate {
    pub(crate) signature: &'static str,
    pub(crate) opening_frame: u64,
    pub(crate) probe_frame: u64,
    pub(crate) evidence_frame: u64,
}

#[derive(Debug)]
pub struct ArpFinding {
    pub involves_announcement: bool,
    pub anomaly: ArpAnomaly,
    pub previous_frame: u64,
    pub correlation_key: String,
}

#[derive(Debug)]
pub struct IdsFinding {
    pub alert: IdsAlert,
    pub related_packets: Vec<u64>,
    pub correlation_key: Option<String>,
}
