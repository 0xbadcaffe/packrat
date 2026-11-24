//! UI-independent passive packet analysis. Capture, persistence, and response
//! policy are adapters; this module never operates a terminal or firewall.

use crate::analysis::alert_center::AlertCenter;
use crate::analysis::carving::{CarvedObject, Carver};
use crate::analysis::impact::EndpointEvidence;
use crate::analysis::incident::{IncidentSource, IncidentStore};
use crate::analysis::ioc::IocEngine;
use crate::analysis::operator_graph::OperatorGraphEngine;
use crate::analysis::quic_scope::QuicScope;
use crate::analysis::rules::{Action as RuleAction, RuleEngine};
use crate::analysis::stream::StreamAssembler;
use crate::analysis::timeline::ProtocolTimelines;
use crate::analysis::tls::TlsTracker;
use crate::analysis::vlan::VlanIntel;
use crate::analysis::yara::YaraEngine;
use crate::model::evidence::Severity as EvidenceSeverity;
use crate::model::hosts::HostInventory;
use crate::net::flow::FlowTracker;
use crate::net::inspector::CredentialHit;
use crate::net::packet::Packet;
use crate::net::security::SecurityEngine;

mod alert_write_backlog;
mod artifacts;
mod graph;
mod inspect;
mod maintenance;
pub mod shared;
pub mod snapshot;
mod transactions;
pub mod worker;

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub enum PacketDisposition {
    #[default]
    Analyzed,
    UnsupportedLinkType(u32),
    MissingTimestamp,
    InvalidTimestamp,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IncidentNotice {
    pub id: u64,
    pub label: String,
    pub auto_contain_rule: bool,
}

#[derive(Debug, Default, serde::Serialize)]
pub struct PacketAnalysis {
    pub disposition: PacketDisposition,
    pub incidents: Vec<IncidentNotice>,
    pub alert_pins: Vec<u64>,
    #[serde(skip)]
    pub(crate) retained_evidence: Vec<Packet>,
}

pub struct AnalysisCore {
    transaction_cache: transactions::TransactionCache,
    http_auth_evidence: crate::net::recent_evidence::RecentEvidence<2048, 90>,
    maintenance_ticks: u32,
    pub carver: Carver,
    pub carved_objects: Vec<CarvedObject>,
    pub yara_engine: YaraEngine,
    pub yara_scan_cursor: usize,
    pub flow_tracker: FlowTracker,
    pub security: SecurityEngine,
    pub alert_center: AlertCenter,
    pub(crate) alert_jsonl_writer: Option<std::sync::Arc<std::sync::Mutex<crate::storage::alert_jsonl::AlertJsonlWriter>>>,
    pub(crate) alert_save_error: Option<String>,
    pub(crate) alert_save_failures: u64,
    pub(crate) alert_write_backlog: alert_write_backlog::AlertWriteBacklog,
    pub credentials: Vec<CredentialHit>,
    pub hosts: HostInventory,
    pub streams: StreamAssembler,
    pub timeline: ProtocolTimelines,
    pub tls_tracker: TlsTracker,
    pub quic_scope: QuicScope,
    pub vlan_intel: VlanIntel,
    pub ioc_engine: IocEngine,
    pub rule_engine: RuleEngine,
    pub incidents: IncidentStore,
    pub endpoint_evidence: Vec<EndpointEvidence>,
    pub operator_graph: OperatorGraphEngine,
}

impl Default for AnalysisCore {
    fn default() -> Self {
        Self {
            transaction_cache: Default::default(),
            http_auth_evidence: Default::default(),
            maintenance_ticks: 0,
            carver: Carver::default(),
            carved_objects: Vec::new(),
            yara_engine: YaraEngine::default(),
            yara_scan_cursor: 0,
            flow_tracker: FlowTracker::new(),
            security: SecurityEngine::default(),
            alert_center: AlertCenter::default(),
            alert_jsonl_writer: None,
            alert_save_error: None,
            alert_save_failures: 0,
            alert_write_backlog: Default::default(),
            credentials: Vec::new(),
            hosts: HostInventory::default(),
            streams: StreamAssembler::default(),
            timeline: ProtocolTimelines::default(),
            tls_tracker: TlsTracker::default(),
            quic_scope: QuicScope::default(),
            vlan_intel: VlanIntel::default(),
            ioc_engine: IocEngine::default(),
            rule_engine: RuleEngine::default(),
            incidents: IncidentStore::default(),
            endpoint_evidence: Vec::new(),
            operator_graph: OperatorGraphEngine::default(),
        }
    }
}

impl std::fmt::Debug for AnalysisCore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AnalysisCore")
            .field("flows", &self.flow_tracker.len())
            .field("streams", &self.streams.len())
            .field("alerts", &self.alert_center.items.len())
            .field("incidents", &self.incidents.incidents.len())
            .finish_non_exhaustive()
    }
}

impl AnalysisCore {
    pub(crate) fn record_alert_save_failure(&mut self, error: String) {
        self.alert_save_error = Some(error);
        self.alert_save_failures = self.alert_save_failures.saturating_add(1);
    }

    pub fn analyze(&mut self, packet: &Packet) -> PacketAnalysis {
        self.analyze_with_history(packet, std::iter::empty())
    }

    pub fn disposition(packet: &Packet) -> PacketDisposition {
        if !packet.timestamp.is_finite() {
            return PacketDisposition::InvalidTimestamp;
        }
        if let Some(capture) = &packet.capture {
            if capture.link_type != 1 {
                return PacketDisposition::UnsupportedLinkType(capture.link_type);
            }
            if capture.timestamp.is_none() {
                return PacketDisposition::MissingTimestamp;
            }
        }
        PacketDisposition::Analyzed
    }

    /// Reconstruct protocol context from a saved packet subset without producing new findings.
    pub(crate) fn observe_saved_evidence(&mut self, packet: &Packet) {
        if Self::disposition(packet) != PacketDisposition::Analyzed {
            return;
        }
        self.flow_tracker.update(packet);
        self.streams.ingest(packet);
        let dns = self.streams.observe_tcp_dns(packet);
        self.security.observe_saved_dns_context(packet, &dns);
        self.tls_tracker.ingest(packet);
    }

    /// Clear observed traffic without discarding configured rules or keys.
    pub fn clear(&mut self) {
        self.transaction_cache = Default::default();
        self.http_auth_evidence = Default::default();
        self.maintenance_ticks = 0;
        self.carver = Carver::default();
        self.carved_objects.clear();
        self.reset_object_scan();
        self.flow_tracker.clear();
        self.security.clear();
        self.alert_center.clear();
        self.credentials.clear();
        self.hosts.clear();
        self.streams.clear();
        self.timeline.clear();
        self.tls_tracker.clear();
        self.quic_scope.clear();
        self.vlan_intel.clear();
        self.ioc_engine.clear_hits();
        self.rule_engine.clear_hits();
        self.incidents.clear();
        self.operator_graph.clear();
    }
}
