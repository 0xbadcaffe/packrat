//! Nearby saved alerts with a matching recorded transport tuple.

use std::{
    num::NonZeroU64,
    path::{Path, PathBuf},
};

use anyhow::{Result, ensure};
use serde::Serialize;

use super::{
    alert_history::{
        AlertHistoryEntry, AlertHistoryIntegrity, MAX_HISTORY_LIMIT,
        recent_alerts_report_with_budget,
    },
    packet_archive::valid_capture_id,
};
use crate::analysis::alert_center::{AlertDisposition, AlertFlow};

const WINDOW_SECONDS: u64 = 300;
const SCAN_BYTES: NonZeroU64 = NonZeroU64::new(8 * 1024 * 1024).unwrap();
const MAX_MATCHES: usize = 32;

#[derive(Serialize)]
pub struct RelatedAlertReport {
    record_type: &'static str,
    status: &'static str,
    session_id: String,
    capture_id: String,
    anchor_alert_id: u64,
    anchor_flow: Option<AlertFlow>,
    opening_window_seconds: u64,
    sampled_alerts: usize,
    scan_complete: bool,
    integrity: AlertHistoryIntegrity,
    matching_alerts_in_sample: usize,
    matches: Vec<RelatedAlert>,
    limitation: &'static str,
}

#[derive(Serialize)]
struct RelatedAlert {
    alert_id: u64,
    rule_id: Option<String>,
    revision: Option<u16>,
    severity: &'static str,
    disposition: AlertDisposition,
    seconds_from_anchor_opening: f64,
    direction: &'static str,
    evidence_frame_count: usize,
}

fn usable_flow(flow: AlertFlow) -> bool {
    flow.source.port() != 0 && flow.destination.port() != 0 && flow.source != flow.destination
}

fn classify(candidate: AlertHistoryEntry, anchor: AlertFlow, opening: f64) -> Option<RelatedAlert> {
    let flow = candidate.flow.filter(|&flow| usable_flow(flow))?;
    let delta = candidate.first_seen - opening;
    if !delta.is_finite()
        || delta.abs() > WINDOW_SECONDS as f64
        || flow.transport != anchor.transport
    {
        return None;
    }
    let direction = if flow == anchor {
        "same"
    } else if flow.destination == anchor.source && flow.source == anchor.destination {
        "reverse"
    } else {
        return None;
    };
    Some(RelatedAlert {
        alert_id: candidate.alert_id,
        rule_id: candidate.rule_id.filter(|rule| {
            !rule.is_empty()
                && rule.len() <= 128
                && rule
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
        }),
        revision: candidate.revision,
        severity: match candidate.severity.as_str() {
            "CRITICAL" => "CRITICAL",
            "HIGH" => "HIGH",
            "MEDIUM" => "MEDIUM",
            "LOW" => "LOW",
            _ => "UNKNOWN",
        },
        disposition: candidate.disposition,
        seconds_from_anchor_opening: delta,
        direction,
        evidence_frame_count: candidate.evidence_frame_count,
    })
}

pub fn related_alerts(
    previous: &[PathBuf],
    active: &Path,
    session: &str,
    capture: &str,
    anchor_id: u64,
) -> Result<RelatedAlertReport> {
    ensure!(
        anchor_id > 0 && valid_capture_id(session) && valid_capture_id(capture),
        "Expected a positive ID and explicit session and capture IDs"
    );
    let history = recent_alerts_report_with_budget(
        previous,
        active,
        Some(session),
        Some(capture),
        MAX_HISTORY_LIMIT,
        Some(SCAN_BYTES),
    )?;
    let scan_complete = history.integrity.invalid_records == 0
        && history.integrity.oversized_records == 0
        && !history.integrity.stopped_at_limit
        && !history.integrity.stopped_at_scan_budget;
    let anchor = history
        .alerts
        .iter()
        .find(|item| item.alert_id == anchor_id);
    let anchor_flow = anchor
        .and_then(|item| item.flow)
        .filter(|&flow| usable_flow(flow));
    let opening = anchor
        .map(|item| item.first_seen)
        .filter(|time| time.is_finite());
    let status = if anchor.is_none() {
        "anchor_not_in_sample"
    } else if anchor_flow.is_none() || opening.is_none() {
        "anchor_tuple_or_time_unavailable"
    } else {
        "sampled"
    };
    let sampled_alerts = history.alerts.len();
    let mut matches = anchor_flow
        .zip(opening)
        .map_or_else(Vec::new, |(flow, opening)| {
            history
                .alerts
                .into_iter()
                .filter(|alert| alert.alert_id != anchor_id)
                .filter_map(|alert| classify(alert, flow, opening))
                .collect()
        });
    matches.sort_unstable_by(|left, right| {
        left.seconds_from_anchor_opening
            .abs()
            .total_cmp(&right.seconds_from_anchor_opening.abs())
            .then(left.alert_id.cmp(&right.alert_id))
    });
    let matching_alerts_in_sample = matches.len();
    matches.truncate(MAX_MATCHES);
    Ok(RelatedAlertReport {
        record_type: "related_alerts",
        status,
        session_id: session.into(),
        capture_id: capture.into(),
        anchor_alert_id: anchor_id,
        anchor_flow,
        opening_window_seconds: WINDOW_SECONDS,
        sampled_alerts,
        scan_complete,
        integrity: history.integrity,
        matching_alerts_in_sample,
        matches,
        limitation: "Recorded tuple matches do not establish the same connection, VLAN, interface, process, or incident.",
    })
}
