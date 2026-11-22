//! Unified, deterministic queue for findings produced by Packrat analyzers.

use std::collections::HashSet;
use super::alert_provenance::{self, AlertProvenance};

const MAX_ALERTS: usize = 2_000;
const AUTOMATIC_EVIDENCE_PRIORITY: u8 = 80;
pub(crate) const MAX_ALERT_PACKET_REFS: usize = 128;
const EARLY_ALERT_PACKET_REFS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub enum AutomationMode {
    #[default]
    Off,
    Watch,
    Triage,
}

impl AutomationMode {
    pub fn cycle(self) -> Self {
        match self {
            Self::Off => Self::Watch,
            Self::Watch => Self::Triage,
            Self::Triage => Self::Off,
        }
    }
}

impl std::fmt::Display for AutomationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AlertDisposition {
    New,
    Reviewing,
    Confirmed,
    Benign,
    Contained,
    Closed,
}

impl std::fmt::Display for AlertDisposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::New => "NEW",
            Self::Reviewing => "REVIEW",
            Self::Confirmed => "CONFIRMED",
            Self::Benign => "BENIGN",
            Self::Contained => "CONTAINED",
            Self::Closed => "CLOSED",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSeverityFilter {
    All,
    Critical,
    High,
    Medium,
    Low,
}

impl AlertSeverityFilter {
    pub fn cycle(self) -> Self {
        match self {
            Self::All => Self::Critical,
            Self::Critical => Self::High,
            Self::High => Self::Medium,
            Self::Medium => Self::Low,
            Self::Low => Self::All,
        }
    }
}

impl std::fmt::Display for AlertSeverityFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlertItem {
    pub id: u64,
    pub packet_no: u64,
    pub source: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub disposition: AlertDisposition,
    pub priority: u8,
    pub recommendation: Option<String>,
    #[serde(default)]
    pub correlation_key: String,
    #[serde(default = "one")]
    pub hit_count: u64,
    #[serde(default)]
    pub first_packet: u64,
    #[serde(default)]
    pub last_packet: u64,
    #[serde(default)]
    pub first_seen: f64,
    #[serde(default)]
    pub last_seen: f64,
    #[serde(default)]
    pub packet_refs: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<AlertProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<AlertFlow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AlertTransport {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AlertFlow {
    pub transport: AlertTransport,
    pub source: std::net::SocketAddr,
    pub destination: std::net::SocketAddr,
}

impl AlertItem {
    pub(crate) fn evidence_frame_numbers(&self) -> Vec<u64> {
        let mut frames = Vec::with_capacity(self.packet_refs.len() + 3);
        frames.extend([self.first_packet, self.packet_no, self.last_packet]);
        frames.extend(self.packet_refs.iter().copied());
        frames.retain(|&number| number > 0);
        frames.sort_unstable();
        frames.dedup();
        frames
    }
}

fn one() -> u64 { 1 }

#[derive(Debug)]
pub struct AlertCenter {
    pub items: Vec<AlertItem>,
    pub selected: usize,
    pub severity_filter: AlertSeverityFilter,
    pub automation_mode: AutomationMode,
    pub(crate) capture_id: Option<String>,
    next_id: u64,
    fingerprints: HashSet<String>,
    pending_pins: Vec<u64>,
    pending_exports: Vec<AlertItem>,
}

impl Default for AlertCenter {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            selected: 0,
            severity_filter: AlertSeverityFilter::All,
            automation_mode: AutomationMode::Off,
            capture_id: None,
            next_id: 0,
            fingerprints: HashSet::new(),
            pending_pins: Vec::new(),
            pending_exports: Vec::new(),
        }
    }
}

impl AlertCenter {
    pub fn restore(&mut self, mut items: Vec<AlertItem>, automation_mode: AutomationMode) {
        if items.len() > MAX_ALERTS {
            items.drain(..items.len() - MAX_ALERTS);
        }
        self.next_id = items.iter().map(|item| item.id).max().unwrap_or(0);
        for item in &mut items {
            if item.first_packet == 0 { item.first_packet = item.packet_no; }
            if item.last_packet == 0 { item.last_packet = item.packet_no; }
            if item.packet_refs.is_empty() {
                item.packet_refs.push(item.first_packet);
                if item.last_packet != item.first_packet {
                    item.packet_refs.push(item.last_packet);
                }
            }
            if item.packet_refs.len() > MAX_ALERT_PACKET_REFS {
                let end = EARLY_ALERT_PACKET_REFS + item.packet_refs.len() - MAX_ALERT_PACKET_REFS;
                item.packet_refs.drain(EARLY_ALERT_PACKET_REFS..end);
            }
        }
        self.fingerprints = items.iter().map(fingerprint_for).collect();
        self.items = items;
        self.selected = 0;
        self.automation_mode = automation_mode;
        self.pending_pins.clear();
        self.pending_exports.clear();
    }

    pub fn record(
        &mut self,
        packet_no: u64,
        source: impl Into<String>,
        severity: impl Into<String>,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> bool {
        let detail = detail.into();
        self.record_correlated(
            packet_no,
            packet_no as f64,
            source,
            severity,
            title,
            &detail,
            "",
        )
    }

    pub fn record_correlated(
        &mut self,
        packet_no: u64,
        timestamp: f64,
        source: impl Into<String>,
        severity: impl Into<String>,
        title: impl Into<String>,
        detail: impl Into<String>,
        correlation_key: impl Into<String>,
    ) -> bool {
        self.record_correlated_with_evidence(
            (packet_no, &[]),
            timestamp,
            source,
            severity,
            title,
            detail,
            correlation_key,
        )
    }

    pub(crate) fn record_correlated_with_evidence(
        &mut self,
        evidence: (u64, &[u64]),
        timestamp: f64,
        source: impl Into<String>,
        severity: impl Into<String>,
        title: impl Into<String>,
        detail: impl Into<String>,
        correlation_key: impl Into<String>,
    ) -> bool {
        self.record_with_context(
            (evidence.0, evidence.1, None), timestamp, source, severity, title, detail, correlation_key,
        )
    }

    pub(crate) fn record_with_context(
        &mut self,
        evidence: (u64, &[u64], Option<AlertFlow>),
        timestamp: f64,
        source: impl Into<String>,
        severity: impl Into<String>,
        title: impl Into<String>,
        detail: impl Into<String>,
        correlation_key: impl Into<String>,
    ) -> bool {
        let (packet_no, related_packets, flow) = evidence;
        let source = source.into();
        let severity = severity.into().to_uppercase();
        let title = title.into();
        let detail = detail.into();
        let correlation_key = correlation_key.into();
        let capture_id = self.capture_id.as_deref().unwrap_or_default();
        let fingerprint = format!("{capture_id}\0{source}\0{title}\0{correlation_key}");
        if !self.fingerprints.insert(fingerprint) {
            if let Some(item) = self.items.iter_mut().find(|item| {
                item.capture_id == self.capture_id
                    && item.source == source
                    && item.title == title
                    && item.correlation_key == correlation_key
            }) {
                item.packet_no = packet_no;
                item.last_packet = packet_no;
                item.last_seen = timestamp;
                let evidence_changed = retain_packet_refs(item, packet_no, related_packets);
                item.hit_count = item.hit_count.saturating_add(1);
                item.detail = detail;
                item.flow = flow;
                let priority = priority_for(&severity);
                let became_high = item.priority < AUTOMATIC_EVIDENCE_PRIORITY
                    && priority >= AUTOMATIC_EVIDENCE_PRIORITY;
                if priority > item.priority {
                    item.priority = priority;
                    item.severity = severity;
                }
                if self.automation_mode != AutomationMode::Off
                    && item.priority >= AUTOMATIC_EVIDENCE_PRIORITY
                    && (evidence_changed || became_high)
                    && !self.pending_pins.contains(&item.id)
                {
                    self.pending_pins.push(item.id);
                }
                self.pending_exports.push(item.clone());
            }
            return false;
        }
        self.next_id += 1;
        let priority = priority_for(&severity);
        let recommendation = (self.automation_mode == AutomationMode::Triage)
            .then(|| recommendation_for(&source, &severity));
        let provenance = alert_provenance::lookup(&source, &title);
        let mut item = AlertItem {
            id: self.next_id,
            packet_no,
            source,
            severity,
            title,
            detail,
            disposition: AlertDisposition::New,
            priority,
            recommendation,
            correlation_key,
            hit_count: 1,
            first_packet: packet_no,
            last_packet: packet_no,
            first_seen: timestamp,
            last_seen: timestamp,
            packet_refs: Vec::new(),
            capture_id: self.capture_id.clone(),
            provenance,
            flow,
        };
        retain_packet_refs(&mut item, packet_no, related_packets);
        self.pending_exports.push(item.clone());
        self.items.push(item);
        if self.automation_mode != AutomationMode::Off && priority >= AUTOMATIC_EVIDENCE_PRIORITY {
            self.pending_pins.push(self.next_id);
        }
        if self.items.len() > MAX_ALERTS {
            let evicted = self.items.remove(0);
            self.fingerprints.remove(&fingerprint_for(&evicted));
            self.selected = self.selected.saturating_sub(1);
        }
        true
    }

    pub fn visible_indices(&self) -> Vec<usize> {
        self.items.iter().enumerate().filter_map(|(index, item)| {
            let visible = match self.severity_filter {
                AlertSeverityFilter::All => true,
                AlertSeverityFilter::Critical => item.severity == "CRITICAL" || item.severity == "CRIT",
                AlertSeverityFilter::High => item.severity == "HIGH",
                AlertSeverityFilter::Medium => item.severity == "MEDIUM" || item.severity == "WARN",
                AlertSeverityFilter::Low => item.severity == "LOW" || item.severity == "INFO",
            };
            visible.then_some(index)
        }).collect()
    }

    pub fn selected_item(&self) -> Option<&AlertItem> {
        let visible = self.visible_indices();
        visible.get(self.selected).and_then(|index| self.items.get(*index))
    }

    pub fn next(&mut self) {
        let max = self.visible_indices().len().saturating_sub(1);
        self.selected = (self.selected + 1).min(max);
    }

    pub fn previous(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn cycle_severity_filter(&mut self) {
        self.severity_filter = self.severity_filter.cycle();
        self.selected = 0;
    }

    pub fn cycle_automation_mode(&mut self) {
        self.automation_mode = self.automation_mode.cycle();
    }

    pub fn drain_pending_pins(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.pending_pins)
    }

    pub fn drain_pending_exports(&mut self) -> Vec<AlertItem> {
        std::mem::take(&mut self.pending_exports)
    }

    pub fn set_selected_disposition(&mut self, disposition: AlertDisposition) -> bool {
        let Some(index) = self.visible_indices().get(self.selected).copied() else {
            return false;
        };
        self.items[index].disposition = disposition;
        self.pending_exports.push(self.items[index].clone());
        true
    }

    pub fn clear(&mut self) {
        self.items.clear();
        self.fingerprints.clear();
        self.selected = 0;
        self.pending_pins.clear();
        self.pending_exports.clear();
    }
}

fn retain_packet_ref(alert: &mut AlertItem, packet_no: u64) -> bool {
    if packet_no == 0 || alert.packet_refs.contains(&packet_no) {
        return false;
    }
    if alert.packet_refs.len() == MAX_ALERT_PACKET_REFS {
        // Keep the opening context as well as the most recent sightings.
        alert.packet_refs.remove(EARLY_ALERT_PACKET_REFS);
    }
    alert.packet_refs.push(packet_no);
    true
}

fn retain_packet_refs(alert: &mut AlertItem, packet_no: u64, related_packets: &[u64]) -> bool {
    let mut changed = false;
    for &related in related_packets {
        changed |= retain_packet_ref(alert, related);
    }
    changed | retain_packet_ref(alert, packet_no)
}

fn fingerprint_for(item: &AlertItem) -> String {
    format!(
        "{}\0{}\0{}\0{}",
        item.capture_id.as_deref().unwrap_or_default(),
        item.source,
        item.title,
        item.correlation_key
    )
}

fn priority_for(severity: &str) -> u8 {
    match severity {
        "CRITICAL" | "CRIT" => 100,
        "HIGH" => 80,
        "MEDIUM" | "WARN" => 50,
        _ => 20,
    }
}

fn recommendation_for(source: &str, severity: &str) -> String {
    if severity == "CRITICAL" || severity == "CRIT" {
        "Review the triggering packet and retained conversation; require an independent signal before containment".into()
    } else if source == "IOC" {
        "Validate indicator provenance, then inspect related hosts and conversations".into()
    } else if source == "CREDENTIAL" {
        "Confirm exposure, identify the affected identity, and rotate the credential through the owning system".into()
    } else if source == "VLAN" {
        "Inspect tag stack and switch-port policy before escalating as VLAN penetration".into()
    } else {
        "Inspect packet fields and surrounding stream, then confirm or mark benign".into()
    }
}

#[cfg(test)]
#[path = "../../tests/unit/analysis_alert_center_tests.rs"]
mod tests;
