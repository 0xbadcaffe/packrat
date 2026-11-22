use super::{ArpAnomaly, BruteForceAlert, IdsAlert, TlsWeakness, VulnHit};

/// Findings emitted by one inspection, independent of retained history limits.
#[derive(Debug, Default)]
pub struct DetectionBatch {
    pub ids: Vec<IdsFinding>,
    pub arp: Vec<ArpFinding>,
    pub vulnerabilities: Vec<VulnHit>,
    pub authentication: Vec<BruteForceAlert>,
    pub tls: Vec<TlsWeakness>,
}

#[derive(Debug)]
pub struct ArpFinding {
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
