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
    expected_frames: BTreeMap<String, BTreeMap<u64, bool>>,
}

#[derive(Serialize)]
pub(super) struct ReplayEvaluation<'a> {
    pub verdict: &'static str,
    checks: Vec<RuleCheck<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    frame_checks: Vec<FrameCheck<'a>>,
}

#[derive(Serialize)]
struct RuleCheck<'a> {
    rule_id: &'a str,
    expected: u64,
    observed: u64,
}

#[derive(Serialize)]
struct FrameCheck<'a> {
    rule_id: &'a str,
    expected_frames: Vec<u64>,
    missing_frames: Vec<u64>,
    unexpected_openings: u64,
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
            if let Some(matched) = self.expected_frames.get_mut(&rule.rule_id)
                .and_then(|frames| frames.get_mut(&item.packet_no))
            {
                *matched = true;
            }
        }
    }

    pub fn expect_frame(&mut self, specification: &str) -> Result<(), String> {
        let (id, frame) = specification
            .split_once('=')
            .ok_or("--expect-alert-frame requires RULE_ID=FRAME")?;
        if !is_registered_rule_id(id) {
            return Err(format!("Unknown alert rule ID: {id}"));
        }
        let frame = frame.parse::<u64>().ok().filter(|&frame| frame > 0)
            .ok_or_else(|| format!("Invalid expected alert frame: {frame}"))?;
        if self.expected_frames.entry(id.into()).or_default().insert(frame, false).is_some() {
            return Err(format!("Duplicate alert frame expectation for {id} at frame {frame}"));
        }
        Ok(())
    }

    pub fn evaluate(&self, input_complete: bool) -> Option<ReplayEvaluation<'_>> {
        if self.expected.is_empty() && self.expected_frames.is_empty() {
            return None;
        }
        let checks: Vec<_> = self.expected.iter().map(|(rule_id, &expected)| RuleCheck {
            rule_id,
            expected,
            observed: self.rule_counts.get(rule_id).copied().unwrap_or(0),
        }).collect();
        let frame_checks: Vec<_> = self.expected_frames.iter().map(|(rule_id, frames)| {
            let missing_frames: Vec<_> = frames.iter()
                .filter_map(|(&frame, &matched)| (!matched).then_some(frame)).collect();
            let matched = (frames.len() - missing_frames.len()) as u64;
            FrameCheck {
                rule_id,
                expected_frames: frames.keys().copied().collect(),
                missing_frames,
                unexpected_openings: self.rule_counts.get(rule_id).copied().unwrap_or(0)
                    .saturating_sub(matched),
            }
        }).collect();
        let verdict = if !input_complete {
            "inconclusive"
        } else if checks.iter().all(|check| check.expected == check.observed)
            && frame_checks.iter().all(|check| check.missing_frames.is_empty() && check.unexpected_openings == 0)
        {
            "passed"
        } else {
            "failed"
        };
        Some(ReplayEvaluation { verdict, checks, frame_checks })
    }
}
