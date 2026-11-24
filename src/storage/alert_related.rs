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
    alert_center::{AlertDisposition, AlertFlow, AlertItem},
    packet_fields::{CapturedVlanTag, captured_transport_header},
};

#[path = "related_cited_flows.rs"]
mod cited_flows;
use cited_flows::{CitedFlowSearch, CitedFrameMatch};
#[path = "related_candidate_triggers.rs"]
mod candidate_triggers;
use candidate_triggers::CandidateTriggerRecovery;

const WINDOW_SECONDS: u64 = 300;
const SCAN_BYTES: NonZeroU64 = NonZeroU64::new(8 * 1024 * 1024).unwrap();
const MAX_MATCHES: usize = 32;
const MAX_PATH_CHECKS: usize = 128;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate_trigger_recovery: Option<CandidateTriggerRecovery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_path_filter: Option<VerifiedPathFilter>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    captured_path_comparison: Option<CapturedPathComparison>,
}

#[derive(Serialize)]
struct TriggerEvidence {
    frame_number: Option<u64>,
    status: &'static str,
    #[serde(skip)]
    path: Option<CapturePath>,
}

#[derive(PartialEq, Eq)]
struct CapturePath {
    section_id: u32,
    interface_id: u32,
    vlan_stack: Vec<CapturedVlanTag>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum CapturedPathComparison {
    SameObservedPath,
    DifferentObservedPath,
    Unavailable,
}

#[derive(Default, Serialize)]
struct VerifiedPathFilter {
    examined_candidates: usize,
    same_observed_path: usize,
    different_observed_path: usize,
    path_unavailable: usize,
    unchecked_candidates: usize,
}

enum TriggerFrame {
    Missing,
    HeaderUnavailable,
    Transport { flow: AlertFlow, time: Option<f64>, path: CapturePath },
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
    #[serde(skip)]
    derived_from_wire: bool,
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
        captured_path_comparison: None,
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
        derived_from_wire: false,
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
        archive: evidence_archive, verify_triggers, ..RelatedEvidenceOptions::default()
    })
}

#[derive(Default)]
pub struct RelatedEvidenceOptions<'a> {
    pub archive: Option<&'a Path>,
    pub verify_triggers: bool,
    pub match_cited_flows: bool,
    pub recover_candidate_triggers: bool,
    pub require_verified_path: bool,
}

pub fn related_alerts_query(
    previous: &[PathBuf], active: &Path, session: &str, capture: &str, anchor_id: u64,
    options: RelatedEvidenceOptions<'_>,
) -> Result<RelatedAlertReport> {
    ensure!(
        anchor_id > 0 && valid_capture_id(session) && valid_capture_id(capture),
        "Expected a positive ID and explicit session and capture IDs"
    );
    let verify_triggers = options.verify_triggers || options.recover_candidate_triggers || options.require_verified_path;
    ensure!(!(verify_triggers || options.match_cited_flows) || options.archive.is_some(),
        "Trigger verification, candidate recovery, verified paths, and cited-flow matching require an evidence archive");
    let mut seen = HashSet::new();
    let mut anchor = None;
    let mut cited_frames = Vec::new();
    let mut candidates = Vec::new();
    let mut recovery = options.recover_candidate_triggers.then(CandidateTriggerRecovery::default);
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
        } else if let Some(recovery) = &mut recovery {
            recovery.enqueue(alert, flow, time);
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
    let mut archive = options.archive.filter(|_| needs_fallback || ((verify_triggers || options.match_cited_flows) && anchor.is_some()))
        .map(PacketArchive::open_readonly).transpose().map_err(anyhow::Error::msg)?;
    let mut anchor_header = if needs_fallback {
        archive.as_mut().map(|reader| read_trigger(reader, capture, packet_no))
    } else {
        None
    };
    if !verify_triggers && !options.match_cited_flows && anchor_header.as_ref().is_some_and(Result::is_err) {
        anchor_header.take().unwrap()?;
    }
    if let Some(Ok(TriggerFrame::Transport { flow, time: Some(time), .. })) = anchor_header.as_ref() {
        anchor_flow = Some(*flow);
        trigger = Some(*time);
        anchor_source = Some("retained_trigger_frame");
        anchor_frame = Some(packet_no);
    }
    let cited = if options.match_cited_flows {
        archive.as_mut().map(|reader| CitedFlowSearch::read(reader, capture, &cited_frames))
    } else { None };
    let mut status = if anchor.is_none() {
        "anchor_not_in_sample"
    } else if let Some(search) = &cited {
        if search.has_flows() { "sampled" } else { "cited_flow_evidence_unavailable" }
    } else if anchor_flow.is_none() || trigger.is_none() {
        "anchor_tuple_or_time_unavailable"
    } else {
        "sampled"
    };
    let sampled_alerts = seen.len();
    if let Some(recovery) = &mut recovery {
        candidates.extend(recovery.recover(archive.as_mut(), capture));
    }
    let mut matches: Vec<_> = if let Some(search) = &cited {
        candidates.into_iter().filter_map(|alert| search.classify(alert)).collect()
    } else if let Some((flow, trigger)) = anchor_flow.zip(trigger) {
        candidates.into_iter().filter_map(|alert| classify(alert, flow, trigger)).collect()
    } else { Vec::new() };
    let order_by_distance = |left: &RelatedAlert, right: &RelatedAlert| {
        left.distance().total_cmp(&right.distance())
            .then(left.snapshot.alert_id.cmp(&right.snapshot.alert_id))
    };
    matches.sort_unstable_by(order_by_distance);
    let matching_alerts_in_sample = matches.len();
    let mut path_filter = options.require_verified_path.then(|| VerifiedPathFilter {
        unchecked_candidates: matches.len().saturating_sub(MAX_PATH_CHECKS),
        ..VerifiedPathFilter::default()
    });
    matches.truncate(if path_filter.is_some() { MAX_PATH_CHECKS } else { MAX_MATCHES });
    let mut anchor_trigger_evidence = None;
    if verify_triggers && let Some(archive) = &mut archive {
        let expected = anchor_flow.zip(trigger);
        anchor_trigger_evidence = Some(check_trigger(archive, capture, packet_no, expected,
            anchor_header.take(), anchor_source == Some("retained_trigger_frame")));
        let anchor_path = anchor_trigger_evidence.as_ref().and_then(|evidence| evidence.path.as_ref());
        if path_filter.is_some() && status == "sampled" && cited.is_none() && anchor_path.is_none() {
            status = "reference_path_unverified";
        }
        for alert in &mut matches {
            let snapshot = &alert.snapshot;
            let trigger_evidence = check_trigger(archive, capture, snapshot.frame,
                Some((snapshot.flow, snapshot.time)), None, snapshot.derived_from_wire);
            if options.require_verified_path
                && let (Some(search), Some(path)) = (&cited, &trigger_evidence.path)
                && let Some((frame, direction)) = search.nearest_frame(snapshot, Some(path))
            {
                alert.matched_cited_frame = Some(frame);
                alert.direction = direction;
            }
            let reference_path = if let Some(frame) = &alert.matched_cited_frame {
                cited.as_ref().and_then(|search| search.path_for(frame.frame_number))
            } else { anchor_path };
            alert.captured_path_comparison = Some(match reference_path.zip(trigger_evidence.path.as_ref()) {
                Some((reference, observed)) if reference == observed => CapturedPathComparison::SameObservedPath,
                Some(_) => CapturedPathComparison::DifferentObservedPath,
                None => CapturedPathComparison::Unavailable,
            });
            alert.trigger_evidence = Some(trigger_evidence);
        }
    }
    if let Some(filter) = &mut path_filter {
        filter.examined_candidates = matches.len();
        matches.retain(|candidate| match candidate.captured_path_comparison {
            Some(CapturedPathComparison::SameObservedPath) => { filter.same_observed_path += 1; true }
            Some(CapturedPathComparison::DifferentObservedPath) => { filter.different_observed_path += 1; false }
            _ => { filter.path_unavailable += 1; false }
        });
        if cited.is_some() {
            matches.sort_unstable_by(order_by_distance);
        }
        matches.truncate(MAX_MATCHES);
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
        candidate_trigger_recovery: recovery,
        verified_path_filter: path_filter,
        trigger_window_seconds: WINDOW_SECONDS,
        sampled_alerts,
        scan_complete,
        integrity,
        matching_alerts_in_sample,
        matches,
        limitation: "Tuple matches use only sampled alerts. A matching observed path is not proof of the same connection, process, or incident.",
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
        let capture = packet.capture.as_ref()?;
        let flow = AlertFlow::from_captured_header(&wire)?;
        let time = packet.timestamp;
        Some(TriggerFrame::Transport {
            flow, time: (time.is_finite() && time > 0.0).then_some(time),
            path: CapturePath { section_id: capture.section_id, interface_id: capture.interface_id, vlan_stack: wire.vlan_stack },
        })
    })();
    Ok(header.unwrap_or(TriggerFrame::HeaderUnavailable))
}

fn check_trigger(
    archive: &mut PacketArchive, capture: &str, frame: u64, expected: Option<(AlertFlow, f64)>,
    cached: Option<Result<TriggerFrame>>, derived: bool,
) -> TriggerEvidence {
    let mut verified_path = None;
    let status = if frame == 0 { "not_referenced" } else {
        match cached.unwrap_or_else(|| read_trigger(archive, capture, frame)) {
            Err(_) => "read_failed",
            Ok(TriggerFrame::Missing) => "missing_frame",
            Ok(TriggerFrame::HeaderUnavailable) => "header_unavailable",
            Ok(TriggerFrame::Transport { flow, time, path }) => match (expected, time) {
                (Some((saved, _)), _) if saved != flow => "tuple_differs_from_wire",
                (_, None) => "timestamp_unavailable",
                (Some((_, saved_time)), Some(time)) if (saved_time - time).abs() > TRIGGER_TIMESTAMP_TOLERANCE_SECONDS => "timestamp_differs_from_wire",
                (Some(_), Some(_)) => {
                    verified_path = Some(path);
                    if derived { "derived_from_wire" } else { "matches_wire" }
                }
                (None, Some(_)) => "recorded_tuple_or_time_unavailable",
            },
        }
    };
    TriggerEvidence { frame_number: (frame > 0).then_some(frame), status, path: verified_path }
}
