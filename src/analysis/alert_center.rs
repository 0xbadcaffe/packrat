//! Unified, deterministic queue for findings produced by Packrat analyzers.

use std::collections::HashSet;

const MAX_ALERTS: usize = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone)]
pub struct AlertItem {
    pub id: u64,
    pub packet_no: u64,
    pub source: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub disposition: AlertDisposition,
}

#[derive(Debug)]
pub struct AlertCenter {
    pub items: Vec<AlertItem>,
    pub selected: usize,
    pub severity_filter: AlertSeverityFilter,
    next_id: u64,
    fingerprints: HashSet<String>,
}

impl Default for AlertCenter {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            selected: 0,
            severity_filter: AlertSeverityFilter::All,
            next_id: 0,
            fingerprints: HashSet::new(),
        }
    }
}

impl AlertCenter {
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
        self.items.push(AlertItem {
            id: self.next_id,
            packet_no,
            source,
            severity,
            title,
            detail: detail.into(),
            disposition: AlertDisposition::New,
        });
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
}
