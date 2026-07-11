//! Critical-alert incident tracking with bounded packet-history retention.
//!
//! Capture and detection remain passive. An incident is evidence for operator
//! review; a future enforcement backend may consume acknowledged policy data,
//! but never changes traffic from this module.

use crate::model::evidence::Severity;
use crate::net::packet::Packet;

const MAX_INCIDENTS: usize = 250;
const MAX_HISTORY_PACKETS: usize = 2_000;
const INITIAL_HISTORY_PACKETS: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IncidentSource {
    IndustrySignature,
    UserRule,
}

impl std::fmt::Display for IncidentSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IndustrySignature => write!(f, "built-in signature"),
            Self::UserRule => write!(f, "user rule"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentStatus {
    PendingReview,
    Acknowledged,
}

impl std::fmt::Display for IncidentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PendingReview => write!(f, "pending review"),
            Self::Acknowledged => write!(f, "acknowledged"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Incident {
    pub id: u64,
    pub source: IncidentSource,
    pub detector: String,
    pub summary: String,
    pub severity: Severity,
    pub attacker: String,
    pub target: String,
    pub first_packet: u64,
    pub last_packet: u64,
    pub first_seen: f64,
    pub last_seen: f64,
    pub status: IncidentStatus,
    pub reviewed: bool,
    pub packet_history: Vec<Packet>,
}

#[derive(Debug, Default)]
pub struct IncidentStore {
    pub incidents: Vec<Incident>,
    active_incident_id: Option<u64>,
    next_id: u64,
}

impl IncidentStore {
    pub fn active(&self) -> Option<&Incident> {
        self.active_incident_id
            .and_then(|id| self.incidents.iter().find(|incident| incident.id == id))
    }

    pub fn active_mut(&mut self) -> Option<&mut Incident> {
        let id = self.active_incident_id?;
        self.incidents.iter_mut().find(|incident| incident.id == id)
    }

    pub fn has_pending(&self) -> bool {
        self.incidents.iter().any(|incident| incident.status == IncidentStatus::PendingReview)
    }

    pub fn open_or_update(
        &mut self,
        source: IncidentSource,
        detector: impl Into<String>,
        summary: impl Into<String>,
        severity: Severity,
        packet: &Packet,
        prior_packets: impl Iterator<Item = Packet>,
    ) -> u64 {
        let detector = detector.into();
        if let Some(existing) = self.incidents.iter_mut().find(|incident| {
            incident.status == IncidentStatus::PendingReview
                && incident.source == source
                && incident.detector == detector
                && incident.attacker == packet.src
                && incident.target == packet.dst
        }) {
            existing.last_packet = packet.no;
            existing.last_seen = packet.timestamp;
            retain_packet(existing, packet.clone());
            return existing.id;
        }

        self.next_id += 1;
        let id = self.next_id;
        let mut incident = Incident {
            id,
            source,
            detector,
            summary: summary.into(),
            severity,
            attacker: packet.src.clone(),
            target: packet.dst.clone(),
            first_packet: packet.no,
            last_packet: packet.no,
            first_seen: packet.timestamp,
            last_seen: packet.timestamp,
            status: IncidentStatus::PendingReview,
            reviewed: false,
            packet_history: Vec::new(),
        };

        let attacker = incident.attacker.clone();
        for prior in prior_packets
            .filter(|prior| prior.src == attacker || prior.dst == attacker)
            .take(INITIAL_HISTORY_PACKETS)
        {
            retain_packet(&mut incident, prior);
        }
        retain_packet(&mut incident, packet.clone());

        if self.incidents.len() >= MAX_INCIDENTS {
            self.incidents.remove(0);
        }
        self.incidents.push(incident);
        if self.active_incident_id.is_none() {
            self.active_incident_id = Some(id);
        }
        id
    }

    /// Add any traffic involving an open incident's suspected attacker.
    pub fn retain_packet(&mut self, packet: &Packet) {
        for incident in self.incidents.iter_mut().filter(|incident| {
            incident.status == IncidentStatus::PendingReview && same_conversation(incident, packet)
        }) {
            incident.last_packet = packet.no;
            incident.last_seen = packet.timestamp;
            retain_packet(incident, packet.clone());
        }
    }

    pub fn mark_active_reviewed(&mut self) -> bool {
        let Some(incident) = self.active_mut() else { return false; };
        incident.reviewed = true;
        true
    }

    pub fn acknowledge_active(&mut self) -> Result<(), &'static str> {
        let Some(incident) = self.active_mut() else { return Err("no active incident"); };
        if !incident.reviewed {
            return Err("review the incident analysis before acknowledging it");
        }
        incident.status = IncidentStatus::Acknowledged;
        self.active_incident_id = self.incidents.iter()
            .find(|candidate| candidate.status == IncidentStatus::PendingReview)
            .map(|candidate| candidate.id);
        Ok(())
    }

    pub fn clear(&mut self) {
        self.incidents.clear();
        self.active_incident_id = None;
    }
}

fn same_conversation(incident: &Incident, packet: &Packet) -> bool {
    packet.src == incident.attacker || packet.dst == incident.attacker
}

fn retain_packet(incident: &mut Incident, packet: Packet) {
    if incident.packet_history.last().is_some_and(|last| last.no == packet.no) {
        return;
    }
    if incident.packet_history.len() >= MAX_HISTORY_PACKETS {
        incident.packet_history.remove(0);
    }
    incident.packet_history.push(packet);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(no: u64, src: &str, dst: &str) -> Packet {
        Packet {
            no,
            timestamp: no as f64,
            src: src.into(),
            dst: dst.into(),
            protocol: "TCP".into(),
            length: 60,
            info: String::new(),
            src_port: Some(12345),
            dst_port: Some(443),
            vlan_id: None,
            vlan_pcp: None,
            vlan_dei: None,
            outer_vlan_id: None,
            bytes: Vec::new(),
        }
    }

    #[test]
    fn retains_conversation_history_and_requires_review_before_acknowledgement() {
        let mut store = IncidentStore::default();
        let current = packet(3, "203.0.113.7", "10.0.0.5");
        store.open_or_update(
            IncidentSource::IndustrySignature,
            "Test signature",
            "test finding",
            Severity::Critical,
            &current,
            vec![packet(1, "203.0.113.7", "10.0.0.5"), packet(2, "10.0.0.5", "203.0.113.7")].into_iter(),
        );

        assert_eq!(store.active().unwrap().packet_history.len(), 3);
        assert!(store.acknowledge_active().is_err());
        assert!(store.mark_active_reviewed());
        assert!(store.acknowledge_active().is_ok());
        assert!(!store.has_pending());
        assert_eq!(store.incidents[0].status, IncidentStatus::Acknowledged);
    }

    #[test]
    fn deduplicates_repeated_pending_finding() {
        let mut store = IncidentStore::default();
        let first = packet(1, "203.0.113.7", "10.0.0.5");
        let second = packet(2, "203.0.113.7", "10.0.0.5");
        store.open_or_update(IncidentSource::UserRule, "rule-1", "first", Severity::Critical, &first, std::iter::empty());
        store.open_or_update(IncidentSource::UserRule, "rule-1", "second", Severity::Critical, &second, std::iter::empty());

        assert_eq!(store.incidents.len(), 1);
        assert_eq!(store.active().unwrap().last_packet, 2);
    }
}
