//! Unified, deterministic queue for findings produced by Packrat analyzers.

use std::collections::HashSet;

const MAX_ALERTS: usize = 2_000;

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
}

#[derive(Debug)]
pub struct AlertCenter {
    pub items: Vec<AlertItem>,
    pub selected: usize,
    pub severity_filter: AlertSeverityFilter,
    pub automation_mode: AutomationMode,
    next_id: u64,
    fingerprints: HashSet<String>,
    pending_pins: Vec<u64>,
}

impl Default for AlertCenter {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            selected: 0,
            severity_filter: AlertSeverityFilter::All,
            automation_mode: AutomationMode::Off,
            next_id: 0,
            fingerprints: HashSet::new(),
            pending_pins: Vec::new(),
        }
    }
}

impl AlertCenter {
    pub fn restore(&mut self, mut items: Vec<AlertItem>, automation_mode: AutomationMode) {
        if items.len() > MAX_ALERTS {
            items.drain(..items.len() - MAX_ALERTS);
        }
        self.next_id = items.iter().map(|item| item.id).max().unwrap_or(0);
        self.fingerprints = items.iter().map(|item| {
            format!("{}\0{}\0{}", item.packet_no, item.source, item.title)
        }).collect();
        self.items = items;
        self.selected = 0;
        self.automation_mode = automation_mode;
        self.pending_pins.clear();
    }

    pub fn record(
        &mut self,
        packet_no: u64,
        source: impl Into<String>,
        severity: impl Into<String>,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> bool {
        let source = source.into();
        let severity = severity.into().to_uppercase();
        let title = title.into();
        let fingerprint = format!("{packet_no}\0{source}\0{title}");
        if !self.fingerprints.insert(fingerprint) {
            return false;
        }
        self.next_id += 1;
        let priority = priority_for(&severity);
        let recommendation = (self.automation_mode == AutomationMode::Triage)
            .then(|| recommendation_for(&source, &severity));
        self.items.push(AlertItem {
            id: self.next_id,
            packet_no,
            source,
            severity,
            title,
            detail: detail.into(),
            disposition: AlertDisposition::New,
            priority,
            recommendation,
        });
        if self.automation_mode != AutomationMode::Off && priority >= 80 {
            self.pending_pins.push(self.next_id);
        }
        if self.items.len() > MAX_ALERTS {
            self.items.remove(0);
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

    pub fn set_selected_disposition(&mut self, disposition: AlertDisposition) -> bool {
        let Some(index) = self.visible_indices().get(self.selected).copied() else {
            return false;
        };
        self.items[index].disposition = disposition;
        true
    }

    pub fn clear(&mut self) {
        self.items.clear();
        self.fingerprints.clear();
        self.selected = 0;
        self.pending_pins.clear();
    }
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
mod tests {
    use super::*;

    #[test]
    fn deduplicates_findings_and_preserves_disposition() {
        let mut center = AlertCenter::default();
        assert!(center.record(7, "IDS", "CRITICAL", "Probe", "first"));
        assert!(!center.record(7, "IDS", "CRITICAL", "Probe", "duplicate"));
        assert!(center.set_selected_disposition(AlertDisposition::Reviewing));
        assert_eq!(center.selected_item().unwrap().disposition, AlertDisposition::Reviewing);
    }

    #[test]
    fn severity_filter_resets_and_bounds_selection() {
        let mut center = AlertCenter::default();
        center.record(1, "IDS", "LOW", "Low", "detail");
        center.record(2, "IDS", "CRITICAL", "Critical", "detail");
        center.next();
        center.cycle_severity_filter();
        assert_eq!(center.severity_filter, AlertSeverityFilter::Critical);
        assert_eq!(center.selected, 0);
        assert_eq!(center.selected_item().unwrap().packet_no, 2);
        center.next();
        assert_eq!(center.selected, 0);
    }

    #[test]
    fn watch_pins_high_findings_and_triage_adds_deterministic_advice() {
        let mut center = AlertCenter::default();
        center.automation_mode = AutomationMode::Watch;
        center.record(1, "IDS", "LOW", "Low", "detail");
        center.record(2, "IDS", "HIGH", "High", "detail");
        assert_eq!(center.drain_pending_pins(), vec![2]);
        assert!(center.items[1].recommendation.is_none());

        center.automation_mode = AutomationMode::Triage;
        center.record(3, "IOC", "HIGH", "Indicator", "detail");
        assert_eq!(center.items[2].priority, 80);
        assert!(center.items[2].recommendation.as_deref().unwrap().contains("provenance"));
    }

    #[test]
    fn restored_alerts_continue_with_unique_ids_and_deduplication() {
        let mut original = AlertCenter::default();
        original.record(7, "IDS", "HIGH", "Probe", "detail");
        original.items[0].disposition = AlertDisposition::Reviewing;

        let mut restored = AlertCenter::default();
        restored.restore(original.items.clone(), AutomationMode::Triage);
        assert!(!restored.record(7, "IDS", "HIGH", "Probe", "duplicate"));
        assert!(restored.record(8, "IDS", "HIGH", "Probe", "new packet"));
        assert_eq!(restored.items[1].id, 2);
        assert_eq!(restored.items[0].disposition, AlertDisposition::Reviewing);
    }
}
