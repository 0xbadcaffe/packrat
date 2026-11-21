use std::collections::BTreeMap;

use packrat_tui::analysis::alert_center::AlertItem;
use packrat_tui::analysis::alert_provenance::is_registered_rule_id;
use serde::Serialize;

#[derive(Default)]
pub(super) struct ReplayAlerts {
    pub opened: u64,
    pub snapshots: u64,
    pub rule_counts: BTreeMap<String, u64>,
    expected: BTreeMap<String, u64>,
}

#[derive(Serialize)]
pub(super) struct ReplayEvaluation<'a> {
    pub verdict: &'static str,
    checks: Vec<RuleCheck<'a>>,
}

#[derive(Serialize)]
struct RuleCheck<'a> {
    rule_id: &'a str,
    expected: u64,
    observed: u64,
}

impl ReplayAlerts {
    pub fn expect(&mut self, specification: &str) -> Result<(), String> {
        let (id, count) = specification
            .split_once('=')
            .ok_or("--expect-alert requires RULE_ID=COUNT")?;
        if !is_registered_rule_id(id) {
            return Err(format!("Unknown alert rule ID: {id}"));
        }
        let count = count
            .parse::<u64>()
            .map_err(|_| format!("Invalid expected alert count: {count}"))?;
        if self.expected.insert(id.into(), count).is_some() {
            return Err(format!("Duplicate alert expectation for {id}"));
        }
        Ok(())
    }

    pub fn observe(&mut self, item: &AlertItem) {
        self.snapshots = self.snapshots.saturating_add(1);
        if item.hit_count != 1 {
            return;
        }
        self.opened = self.opened.saturating_add(1);
        if let Some(rule) = &item.provenance {
            let count = self.rule_counts.entry(rule.rule_id.clone()).or_default();
            *count = count.saturating_add(1);
        }
    }

    pub fn evaluate(&self, input_complete: bool) -> Option<ReplayEvaluation<'_>> {
        if self.expected.is_empty() {
            return None;
        }
        let checks: Vec<_> = self.expected.iter().map(|(rule_id, &expected)| RuleCheck {
            rule_id,
            expected,
            observed: self.rule_counts.get(rule_id).copied().unwrap_or(0),
        }).collect();
        let verdict = if !input_complete {
            "inconclusive"
        } else if checks.iter().all(|check| check.expected == check.observed) {
            "passed"
        } else {
            "failed"
        };
        Some(ReplayEvaluation { verdict, checks })
    }
}
