//! Nearby saved alerts with a matching recorded transport tuple.

use std::{
    collections::HashSet,
    num::NonZeroU64,
    path::{Path, PathBuf},
};

use anyhow::{Result, ensure};
use serde::Serialize;

use super::{
    alert_history::{AlertHistoryIntegrity, scan_alert_records},
    packet_archive::valid_capture_id,
};
use crate::analysis::alert_center::{AlertDisposition, AlertFlow, AlertItem};

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
    anchor_trigger_time: Option<f64>,
    trigger_window_seconds: u64,
    sampled_alerts: usize,
    scan_complete: bool,
    integrity: AlertHistoryIntegrity,
    matching_alerts_in_sample: usize,
    matches: Vec<RelatedAlert>,
    limitation: &'static str,
}

#[derive(Serialize)]
struct RelatedAlert {
    #[serde(flatten)]
    snapshot: TriggerSnapshot,
    seconds_from_anchor_trigger: f64,
    direction: &'static str,
}

#[derive(Serialize)]
struct TriggerSnapshot {
    alert_id: u64,
    rule_id: Option<String>,
    revision: Option<u16>,
    severity: &'static str,
    disposition: AlertDisposition,
    evidence_frame_count: usize,
    #[serde(skip)]
    flow: AlertFlow,
    #[serde(skip)]
    time: f64,
}

fn usable_flow(flow: AlertFlow) -> bool {
    flow.source.port() != 0 && flow.destination.port() != 0 && flow.source != flow.destination
}

// AlertCenter replaces flow and last_seen together when a newer hit is recorded.
fn trigger_time(alert: &AlertItem) -> Option<f64> {
    let time = alert.last_seen;
    (time.is_finite() && time != 0.0).then_some(time)
}

fn classify(snapshot: TriggerSnapshot, anchor: AlertFlow, trigger: f64) -> Option<RelatedAlert> {
    let flow = snapshot.flow;
    let delta = snapshot.time - trigger;
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
        snapshot,
        seconds_from_anchor_trigger: delta,
        direction,
    })
}

fn snapshot(alert: &AlertItem, flow: AlertFlow, time: f64) -> TriggerSnapshot {
    let provenance = alert
        .provenance
        .as_ref()
        .filter(|_| alert.source != "CREDENTIAL");
    TriggerSnapshot {
        alert_id: alert.id,
        rule_id: provenance
            .map(|rule| &rule.rule_id)
            .filter(|rule| {
                !rule.is_empty()
                    && rule.len() <= 128
                    && rule
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
            })
            .cloned(),
        revision: provenance.map(|rule| rule.revision),
        severity: match alert.severity.as_str() {
            "CRITICAL" => "CRITICAL",
            "HIGH" => "HIGH",
            "MEDIUM" => "MEDIUM",
            "LOW" => "LOW",
            _ => "UNKNOWN",
        },
        disposition: alert.disposition,
        evidence_frame_count: alert.evidence_frame_numbers().len(),
        flow,
        time,
    }
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
    let mut seen = HashSet::new();
    let mut anchor = None;
    let mut candidates = Vec::new();
    let integrity = scan_alert_records(previous, active, Some(SCAN_BYTES), |entry| {
        let alert = entry.alert;
        if entry.session_id != session
            || alert.capture_id.as_deref() != Some(capture)
            || alert.id == 0
            || !seen.insert(alert.id)
        {
            return false;
        }
        // Deduplicate before checking the tuple so an obsolete match never wins.
        let flow = alert.flow.filter(|&flow| usable_flow(flow));
        let time = trigger_time(&alert);
        if alert.id == anchor_id {
            anchor = Some((flow, time));
        } else if let Some((flow, time)) = flow.zip(time) {
            candidates.push(snapshot(&alert, flow, time));
        }
        false
    })?;
    let scan_complete = integrity.invalid_records == 0
        && integrity.oversized_records == 0
        && !integrity.stopped_at_scan_budget;
    let (anchor_flow, trigger) = anchor.unwrap_or_default();
    let status = if anchor.is_none() {
        "anchor_not_in_sample"
    } else if anchor_flow.is_none() || trigger.is_none() {
        "anchor_tuple_or_time_unavailable"
    } else {
        "sampled"
    };
    let sampled_alerts = seen.len();
    let mut matches = anchor_flow
        .zip(trigger)
        .map_or_else(Vec::new, |(flow, trigger)| {
            candidates
                .into_iter()
                .filter_map(|alert| classify(alert, flow, trigger))
                .collect()
        });
    matches.sort_unstable_by(|left, right| {
        left.seconds_from_anchor_trigger
            .abs()
            .total_cmp(&right.seconds_from_anchor_trigger.abs())
            .then(left.snapshot.alert_id.cmp(&right.snapshot.alert_id))
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
        anchor_trigger_time: trigger.filter(|_| anchor_flow.is_some()),
        trigger_window_seconds: WINDOW_SECONDS,
        sampled_alerts,
        scan_complete,
        integrity,
        matching_alerts_in_sample,
        matches,
        limitation: "Recorded tuple matches do not establish the same connection, VLAN, interface, process, or incident.",
    })
}
