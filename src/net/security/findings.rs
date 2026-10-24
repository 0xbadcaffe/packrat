use super::{ArpAnomaly, BruteForceAlert, IdsAlert, TlsWeakness, VulnHit};

/// Findings emitted by one inspection, independent of retained history limits.
#[derive(Debug, Default)]
pub struct DetectionBatch {
    pub ids: Vec<IdsAlert>,
    pub arp: Vec<ArpAnomaly>,
    pub vulnerabilities: Vec<VulnHit>,
    pub authentication: Vec<BruteForceAlert>,
    pub tls: Vec<TlsWeakness>,
}
