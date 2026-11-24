use std::collections::BTreeMap;

use packrat_tui::analysis::alert_center::AlertItem;
use packrat_tui::analysis::alert_provenance::is_registered_rule_id;
use packrat_tui::analysis::dns_transactions::DnsCapacityStats;
use serde::Serialize;

#[derive(Default)]
pub(super) struct ReplayAlerts {
    pub opened: u64,
    pub snapshots: u64,
    pub rule_counts: BTreeMap<String, u64>,
    highest_alert_id: u64,
    expected: BTreeMap<String, u64>,
    expected_frames: BTreeMap<String, BTreeMap<u64, bool>>,
}

#[derive(Serialize)]
pub(super) struct ReplayEvaluation<'a> {
    pub verdict: &'static str,
    dns_capacity_limited_rules: Vec<&'a str>,
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

    pub fn observe(&mut self, item: &AlertItem) -> bool {
        self.snapshots = self.snapshots.saturating_add(1);
        // One offline capture owns a monotonic alert ID space, including evidence-only snapshots.
        if item.id <= self.highest_alert_id {
            return false;
        }
        self.highest_alert_id = item.id;
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
        true
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

    pub fn evaluate(&self, input_complete: bool, dns: DnsCapacityStats) -> Option<ReplayEvaluation<'_>> {
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
        let mut dns_capacity_limited_rules: Vec<_> = self.expected.keys().chain(self.expected_frames.keys())
            .map(String::as_str).filter(|id| dns_rule_limited(id, dns)).collect();
        dns_capacity_limited_rules.sort_unstable();
        dns_capacity_limited_rules.dedup();
        let verdict = if !input_complete || !dns_capacity_limited_rules.is_empty() {
            "inconclusive"
        } else if checks.iter().all(|check| check.expected == check.observed)
            && frame_checks.iter().all(|check| check.missing_frames.is_empty() && check.unexpected_openings == 0)
        {
            "passed"
        } else {
            "failed"
        };
        Some(ReplayEvaluation { verdict, checks, frame_checks, dns_capacity_limited_rules })
    }
}

fn dns_rule_limited(id: &str, dns: DnsCapacityStats) -> bool {
    let query_limited = dns.query_key_declines > 0 || dns.query_candidate_declines > 0;
    match id {
        "dns.nxdomain_distinct_names" => query_limited || dns.nxdomain_client_declines > 0,
        "dns.external_resolver_exchange" => query_limited || dns.external_resolver_pair_declines > 0,
        "dns.competing_responders" | "dns.changed_answers" | "dns.changed_wire_reply"
        | "dns.question_mismatch" | "dns.unexpected_responder" | "dns.unmatched_response"
        | "dns.ambiguous_reply" | "dns.large_txt_answer" => query_limited,
        _ => false,
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/replay_dns_capacity_tests.rs"]
mod tests;
