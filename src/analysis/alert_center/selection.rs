use super::{AlertCenter, AlertItem, AlertSeverityFilter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertReviewFilter {
    All,
    Open,
    Resolved,
}

impl std::fmt::Display for AlertReviewFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl AlertCenter {
    pub(super) fn is_visible(&self, item: &AlertItem) -> bool {
        let severity = match self.severity_filter {
            AlertSeverityFilter::All => true,
            AlertSeverityFilter::Critical => matches!(item.severity.as_str(), "CRITICAL" | "CRIT"),
            AlertSeverityFilter::High => item.severity == "HIGH",
            AlertSeverityFilter::Medium => matches!(item.severity.as_str(), "MEDIUM" | "WARN"),
            AlertSeverityFilter::Low => matches!(item.severity.as_str(), "LOW" | "INFO"),
        };
        severity && match self.review_filter {
            AlertReviewFilter::All => true,
            AlertReviewFilter::Open => !item.disposition.is_resolved(),
            AlertReviewFilter::Resolved => item.disposition.is_resolved(),
        }
    }

    pub fn visible_indices(&self) -> Vec<usize> {
        self.items.iter().enumerate().filter_map(|(index, item)| {
            self.is_visible(item).then_some(index)
        }).collect()
    }

    pub fn selected_item(&self) -> Option<&AlertItem> {
        self.items.iter().filter(|item| self.is_visible(item)).nth(self.selected)
    }

    pub(super) fn filtered_selection_anchor(&self) -> Option<usize> {
        if self.severity_filter == AlertSeverityFilter::All && self.review_filter == AlertReviewFilter::All {
            return None;
        }
        self.items.iter().enumerate().filter(|(_, item)| self.is_visible(item))
            .nth(self.selected).map(|(index, _)| index)
    }

    pub(super) fn restore_filtered_selection(&mut self, anchor: Option<usize>) {
        if let Some(index) = anchor {
            let visible = self.visible_indices();
            self.selected = visible.partition_point(|&candidate| candidate < index)
                .min(visible.len().saturating_sub(1));
        }
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

    pub fn cycle_review_filter(&mut self) {
        self.review_filter = match self.review_filter {
            AlertReviewFilter::All => AlertReviewFilter::Open,
            AlertReviewFilter::Open => AlertReviewFilter::Resolved,
            AlertReviewFilter::Resolved => AlertReviewFilter::All,
        };
        self.selected = 0;
    }
}
