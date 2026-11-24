//! Nearby saved alerts with a matching trigger transport tuple.

use std::{
    collections::HashSet,
    num::NonZeroU64,
    path::{Path, PathBuf},
};

use anyhow::{Result, ensure};
use serde::Serialize;

use super::{
    alert_evidence::{FrameStatus, frame_status},
    alert_history::{AlertHistoryIntegrity, scan_alert_records},
    packet_archive::{PacketArchive, valid_capture_id},
};
use crate::analysis::{
    alert_center::{AlertDisposition, AlertFlow, AlertItem, AlertTransport},
    packet_fields::captured_transport_header,
};

#[path = "related_cited_flows.rs"]
mod cited_flows;
use cited_flows::{CitedFlowSearch, CitedFrameMatch};

const WINDOW_SECONDS: u64 = 300;
const SCAN_BYTES: NonZeroU64 = NonZeroU64::new(8 * 1024 * 1024).unwrap();
const MAX_MATCHES: usize = 32;
const TRIGGER_TIMESTAMP_TOLERANCE_SECONDS: f64 = 0.001;

#[derive(Serialize)]
pub struct RelatedAlertReport {
    record_type: &'static str,
    status: &'static str,
    session_id: String,
    capture_id: String,
    anchor_alert_id: u64,
    anchor_flow: Option<AlertFlow>,
    anchor_trigger_time: Option<f64>,
    anchor_source: Option<&'static str>,
    anchor_frame: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    anchor_trigger_evidence: Option<TriggerEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cited_flow_evidence: Option<CitedFlowSearch>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    seconds_from_anchor_trigger: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    matched_cited_frame: Option<CitedFrameMatch>,
    direction: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    trigger_evidence: Option<TriggerEvidence>,
}

#[derive(Serialize)]
struct TriggerEvidence {
    frame_number: Option<u64>,
    status: &'static str,
}

enum TriggerFrame {
    Missing,
    HeaderUnavailable,
    Transport { flow: AlertFlow, time: Option<f64> },
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
    frame: u64,
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
        seconds_from_anchor_trigger: Some(delta),
        matched_cited_frame: None,
        direction,
        trigger_evidence: None,
    })
}

impl RelatedAlert {
    fn distance(&self) -> f64 {
        self.matched_cited_frame.as_ref().map(|frame| frame.seconds_from_frame)
            .or(self.seconds_from_anchor_trigger).unwrap_or_default().abs()
    }
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
        frame: alert.packet_no,
        flow,
        time,
    }
}

pub fn related_alerts(
    previous: &[PathBuf], active: &Path, session: &str, capture: &str, anchor_id: u64,
) -> Result<RelatedAlertReport> {
    related_alerts_with_evidence(previous, active, session, capture, anchor_id, None)
}

pub fn related_alerts_with_evidence(
    previous: &[PathBuf],
    active: &Path,
    session: &str,
    capture: &str,
    anchor_id: u64,
    evidence_archive: Option<&Path>,
) -> Result<RelatedAlertReport> {
    related_alerts_report(previous, active, session, capture, anchor_id, evidence_archive, false)
}

pub fn related_alerts_report(
    previous: &[PathBuf], active: &Path, session: &str, capture: &str, anchor_id: u64,
    evidence_archive: Option<&Path>, verify_triggers: bool,
) -> Result<RelatedAlertReport> {
    related_alerts_query(previous, active, session, capture, anchor_id, RelatedEvidenceOptions {
        archive: evidence_archive, verify_triggers, match_cited_flows: false,
    })
}

#[derive(Default)]
pub struct RelatedEvidenceOptions<'a> {
    pub archive: Option<&'a Path>,
    pub verify_triggers: bool,
    pub match_cited_flows: bool,
}

pub fn related_alerts_query(
    previous: &[PathBuf], active: &Path, session: &str, capture: &str, anchor_id: u64,
    options: RelatedEvidenceOptions<'_>,
) -> Result<RelatedAlertReport> {
    ensure!(
        anchor_id > 0 && valid_capture_id(session) && valid_capture_id(capture),
        "Expected a positive ID and explicit session and capture IDs"
    );
    ensure!(!(options.verify_triggers || options.match_cited_flows) || options.archive.is_some(),
        "Trigger verification and cited-flow matching require an evidence archive");
    let mut seen = HashSet::new();
    let mut anchor = None;
    let mut cited_frames = Vec::new();
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
            anchor = Some((flow, time, alert.packet_no));
            if options.match_cited_flows { cited_frames = alert.evidence_frame_numbers(); }
        } else if let Some((flow, time)) = flow.zip(time) {
            candidates.push(snapshot(&alert, flow, time));
        }
        false
    })?;
    let scan_complete = integrity.invalid_records == 0
        && integrity.oversized_records == 0
        && !integrity.stopped_at_scan_budget;
    let (mut anchor_flow, mut trigger, packet_no) = anchor.unwrap_or_default();
    let mut anchor_source = anchor_flow.zip(trigger).map(|_| "recorded_alert");
    let mut anchor_frame = None;
    let needs_fallback = anchor_source.is_none() && packet_no > 0;
    let mut archive = options.archive.filter(|_| needs_fallback || ((options.verify_triggers || options.match_cited_flows) && anchor.is_some()))
        .map(PacketArchive::open_readonly).transpose().map_err(anyhow::Error::msg)?;
    let mut anchor_header = if needs_fallback {
        archive.as_mut().map(|reader| read_trigger(reader, capture, packet_no))
    } else {
        None
    };
    if !options.verify_triggers && !options.match_cited_flows && anchor_header.as_ref().is_some_and(Result::is_err) {
        anchor_header.take().unwrap()?;
    }
    if let Some(Ok(TriggerFrame::Transport { flow, time: Some(time) })) = anchor_header.as_ref() {
        anchor_flow = Some(*flow);
        trigger = Some(*time);
        anchor_source = Some("retained_trigger_frame");
        anchor_frame = Some(packet_no);
    }
    let cited = if options.match_cited_flows {
        archive.as_mut().map(|reader| CitedFlowSearch::read(reader, capture, &cited_frames))
    } else { None };
    let status = if anchor.is_none() {
        "anchor_not_in_sample"
    } else if let Some(search) = &cited {
        if search.has_flows() { "sampled" } else { "cited_flow_evidence_unavailable" }
    } else if anchor_flow.is_none() || trigger.is_none() {
        "anchor_tuple_or_time_unavailable"
    } else {
        "sampled"
    };
    let sampled_alerts = seen.len();
    let mut matches: Vec<_> = if let Some(search) = &cited {
        candidates.into_iter().filter_map(|alert| search.classify(alert)).collect()
    } else if let Some((flow, trigger)) = anchor_flow.zip(trigger) {
        candidates.into_iter().filter_map(|alert| classify(alert, flow, trigger)).collect()
    } else { Vec::new() };
    matches.sort_unstable_by(|left, right| {
        left.distance().total_cmp(&right.distance())
            .then(left.snapshot.alert_id.cmp(&right.snapshot.alert_id))
    });
    let matching_alerts_in_sample = matches.len();
    matches.truncate(MAX_MATCHES);
    let mut anchor_trigger_evidence = None;
    if options.verify_triggers && let Some(archive) = &mut archive {
        let expected = anchor_flow.zip(trigger);
        anchor_trigger_evidence = Some(check_trigger(archive, capture, packet_no, expected,
            anchor_header.take(), anchor_source == Some("retained_trigger_frame")));
        for alert in &mut matches {
            let snapshot = &alert.snapshot;
            alert.trigger_evidence = Some(check_trigger(archive, capture, snapshot.frame,
                Some((snapshot.flow, snapshot.time)), None, false));
        }
    }
    Ok(RelatedAlertReport {
        record_type: "related_alerts",
        status,
        session_id: session.into(),
        capture_id: capture.into(),
        anchor_alert_id: anchor_id,
        anchor_flow,
        anchor_trigger_time: trigger.filter(|_| anchor_flow.is_some()),
        anchor_source,
        anchor_frame,
        anchor_trigger_evidence,
        cited_flow_evidence: cited,
        trigger_window_seconds: WINDOW_SECONDS,
        sampled_alerts,
        scan_complete,
        integrity,
        matching_alerts_in_sample,
        matches,
        limitation: "Tuple matches use only sampled alerts and do not establish the same connection, VLAN, interface, process, or incident.",
    })
}

fn read_trigger(archive: &mut PacketArchive, capture: &str, frame: u64) -> Result<TriggerFrame> {
    let Some(packet) = archive.packet_for_capture(capture, frame).map_err(anyhow::Error::msg)? else {
        return Ok(TriggerFrame::Missing);
    };
    let header = (|| {
        if !matches!(frame_status(&packet), FrameStatus::Complete | FrameStatus::Truncated) {
            return None;
        }
        let wire = captured_transport_header(&packet)?;
        let transport = match wire.protocol {
            6 => AlertTransport::Tcp,
            17 => AlertTransport::Udp,
            _ => return None,
        };
        let flow = AlertFlow { transport, source: wire.source, destination: wire.destination };
        let time = packet.timestamp;
        usable_flow(flow).then_some(TriggerFrame::Transport {
            flow, time: (time.is_finite() && time > 0.0).then_some(time),
        })
    })();
    Ok(header.unwrap_or(TriggerFrame::HeaderUnavailable))
}

fn check_trigger(
    archive: &mut PacketArchive, capture: &str, frame: u64, expected: Option<(AlertFlow, f64)>,
    cached: Option<Result<TriggerFrame>>, derived: bool,
) -> TriggerEvidence {
    let status = if frame == 0 { "not_referenced" } else {
        match cached.unwrap_or_else(|| read_trigger(archive, capture, frame)) {
            Err(_) => "read_failed",
            Ok(TriggerFrame::Missing) => "missing_frame",
            Ok(TriggerFrame::HeaderUnavailable) => "header_unavailable",
            Ok(TriggerFrame::Transport { flow, time }) => match (expected, time) {
                (Some((saved, _)), _) if saved != flow => "tuple_differs_from_wire",
                (_, None) => "timestamp_unavailable",
                (Some((_, saved_time)), Some(time)) if (saved_time - time).abs() > TRIGGER_TIMESTAMP_TOLERANCE_SECONDS => "timestamp_differs_from_wire",
                (Some(_), Some(_)) if derived => "derived_from_wire",
                (Some(_), Some(_)) => "matches_wire",
                (None, Some(_)) => "recorded_tuple_or_time_unavailable",
            },
        }
    };
    TriggerEvidence { frame_number: (frame > 0).then_some(frame), status }
}
