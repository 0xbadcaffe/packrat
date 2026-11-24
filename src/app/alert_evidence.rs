use super::*;
use crate::analysis::{
    alert_center::{AlertFlow, AlertItem, AlertTransport},
    packet_fields::captured_transport_header,
};
use crate::storage::alert_evidence::{FrameStatus, frame_status};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AlertEvidenceScope {
    Unscoped,
    CurrentCapture,
    DifferentCapture,
    MissingCaptureId,
}

#[derive(Clone, Copy)]
pub(super) enum LocalAlertPacket {
    Pin(u64),
    Buffer(usize),
}

impl LocalAlertPacket {
    pub(super) fn get(self, app: &App) -> Option<&Packet> {
        match self {
            Self::Pin(frame) => app.worklist.retained_packet(frame),
            Self::Buffer(index) => app.packets.get(index),
        }
    }
}

impl AlertEvidenceScope {
    pub(super) fn local_mismatch(self) -> Option<&'static str> {
        match self {
            Self::DifferentCapture => Some("different capture"),
            Self::MissingCaptureId => Some("capture ID not recorded"),
            Self::Unscoped | Self::CurrentCapture => None,
        }
    }
}

#[derive(Default)]
pub(super) struct AlertEvidenceReader {
    archive: Option<crate::storage::packet_archive::PacketArchive>,
    attempted: bool,
    pub(super) archive_error: bool,
    pub(super) invalid_lengths: usize,
    checks: std::collections::BTreeMap<u64, ArchiveLookup>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ArchiveLookup { Missing, Invalid, ReadFailed, Available }

pub(super) struct AlertArchiveCheck {
    alert_id: u64,
    capture_id: String,
    checks: std::collections::BTreeMap<u64, ArchiveLookup>,
}

impl AlertEvidenceReader {
    pub(super) fn resolve(&mut self, app: &App, alert: &AlertItem, frame: u64, location: Option<LocalAlertPacket>,
    ) -> Option<(Packet, bool, FrameStatus)> {
        let mut invalid = false;
        if let Some(packet) = location.and_then(|slot| slot.get(app)) {
            let status = frame_status(packet);
            if status != FrameStatus::Unreadable { return Some((packet.clone(), false, status)); }
            invalid = true;
        }
        if app.frame_may_be_local(app.alert_evidence_scope(alert), frame)
            && let Some(scope) = alert.capture_id.as_deref()
            && let Some(worker) = &app.packet_archive
        {
            if !self.attempted {
                self.attempted = true;
                match worker.reader() {
                    Ok(archive) => self.archive = Some(archive),
                    Err(_) => self.archive_error = true,
                }
            }
            if let Some(archive) = &mut self.archive {
                match archive.packet_for_capture(scope, frame) {
                    Ok(Some(packet)) => {
                        let status = frame_status(&packet);
                        if status != FrameStatus::Unreadable {
                            self.checks.insert(frame, ArchiveLookup::Available);
                            return Some((packet, true, status));
                        }
                        self.checks.insert(frame, ArchiveLookup::Invalid);
                        invalid = true;
                    }
                    Ok(None) => { self.checks.insert(frame, ArchiveLookup::Missing); }
                    Err(_) => {
                        self.archive_error = true;
                        self.checks.insert(frame, ArchiveLookup::ReadFailed);
                    }
                }
            } else {
                self.checks.insert(frame, ArchiveLookup::ReadFailed);
            }
        }
        self.invalid_lengths += usize::from(invalid);
        None
    }

    pub(super) fn into_archive_check(self, alert: &AlertItem) -> Option<AlertArchiveCheck> {
        if self.checks.is_empty() { return None; }
        Some(AlertArchiveCheck { alert_id: alert.id, capture_id: alert.capture_id.clone()?, checks: self.checks })
    }
}

impl App {
    pub(super) fn archive_alert_packets(&mut self, alert: &AlertItem, evidence: &[Packet]) {
        let Some(archive) = self.packet_archive.as_ref()
            .filter(|archive| archive.alert_evidence_only() && archive.pause_reason().is_none())
        else { return };
        let Some(capture_id) = self.capture_id.as_ref()
            .filter(|scope| alert.capture_id.as_deref() == Some(scope.as_ref()))
        else { return };
        let frames = alert.evidence_frame_numbers();
        let queue = |frame| {
            if !self.frame_may_be_local(AlertEvidenceScope::CurrentCapture, frame) {
                return Ok(());
            }
            let packet = evidence.binary_search_by_key(&frame, |packet| packet.no).ok()
                .map(|index| &evidence[index]).or_else(|| self.packet_by_no(frame));
            packet.map_or(Ok(()), |packet| archive.record_scoped(capture_id, packet))
        };
        let (trigger, others) = (alert.packet_no, frames.iter().copied().filter(|&n| n != alert.packet_no));
        let trigger = frames.binary_search(&trigger).ok().map(|_| trigger);
        for frame in trigger.into_iter().chain(others) {
            if let Err(error) = queue(frame) {
                archive.pause(crate::storage::packet_archive::ArchivePause::QueueUnavailable);
                self.set_status(format!("Alert packet archive paused: {error}; capture continues"));
                break;
            }
        }
    }

    pub(super) fn alert_evidence_scope(&self, alert: &AlertItem) -> AlertEvidenceScope {
        match alert.capture_id.as_deref() {
            None if self.capture_id.is_some() => AlertEvidenceScope::MissingCaptureId,
            None => AlertEvidenceScope::Unscoped,
            scope if scope == self.capture_id.as_deref() => AlertEvidenceScope::CurrentCapture,
            _ => AlertEvidenceScope::DifferentCapture,
        }
    }

    pub(super) fn saved_alert_pin(&self, alert: &AlertItem, frame: u64) -> Option<&Packet> {
        let scope = alert.capture_id.as_deref()?;
        let pin_scope = self.worklist.restored_packet_scopes.get(&frame)?;
        (pin_scope == scope).then(|| self.worklist.retained_packet(frame)).flatten()
    }

    pub(super) fn frame_may_be_local(&self, scope: AlertEvidenceScope, frame: u64) -> bool {
        match scope {
            AlertEvidenceScope::CurrentCapture => frame > self.restored_project_max_frame,
            AlertEvidenceScope::Unscoped => !self.worklist.restored_packet_scopes.contains_key(&frame),
            _ => false,
        }
    }

    fn previous_archive_check(&self, alert: &AlertItem, frame: u64) -> Option<ArchiveLookup> {
        let check = self.last_alert_archive_check.as_ref()?;
        self.packet_archive.as_ref()?;
        if check.alert_id != alert.id || alert.capture_id.as_deref() != Some(check.capture_id.as_str())
            || !self.frame_may_be_local(self.alert_evidence_scope(alert), frame)
        {
            return None;
        }
        check.checks.get(&frame).copied()
    }

    pub(crate) fn alert_evidence_status(&self, alert: &AlertItem) -> String {
        self.describe_alert_evidence(alert, false).0
    }

    pub(super) fn alert_evidence_context(&self, alert: &AlertItem) -> (String, Option<String>) {
        self.describe_alert_evidence(alert, true)
    }

    pub(super) fn matching_saved_alert_archive_report(&self, alert: &AlertItem) -> Option<&crate::model::project::AlertArchiveReport> {
        self.saved_alert_archive_report.as_ref().filter(|report| {
            report.alert_id == alert.id && Some(report.capture_id.as_str()) == alert.capture_id.as_deref()
                && report.frames.keys().copied().eq(alert.evidence_frame_numbers())
        })
    }

    pub(super) fn saved_alert_archive_details(&self, alert: &AlertItem) -> Vec<(String, String)> {
        use crate::model::project::ArchivedFrameOutcome;

        let Some(report) = self.matching_saved_alert_archive_report(alert) else { return Vec::new() };
        let mut details: Vec<_> = [
            (ArchivedFrameOutcome::Missing, "Missing at export"),
            (ArchivedFrameOutcome::Unreadable, "Unreadable at export"),
            (ArchivedFrameOutcome::OmittedAtLimit, "Omitted at export (limit)"),
            (ArchivedFrameOutcome::Truncated, "Truncated at export"),
            (ArchivedFrameOutcome::LengthUnknown, "Length unknown at export"),
        ].into_iter().filter_map(|(kind, label)| {
            let numbers: Vec<_> = report.frames.iter().filter(|(_, status)| **status == kind)
                .map(|(frame, _)| format!("#{frame}")).collect();
            (!numbers.is_empty()).then(|| (label.into(), numbers.join(", ")))
        }).collect();
        if let Some(session) = &report.session_id {
            details.push(("Alert session".into(), session.clone()));
        }
        if let Some(checked) = report.archive_checked {
            details.push(("Archive at export".into(), if checked { "Checked" } else { "Not checked" }.into()));
        }
        if report.frames.values().all(|outcome| outcome.included()) {
            details.push(("Case export".into(), "All cited frames included at export".into()));
        }
        if !report.local_fallback_frames.is_empty() {
            let frames = report.local_fallback_frames.iter().map(|frame| format!("#{frame}")).collect::<Vec<_>>();
            details.push(("Local evidence at export".into(), frames.join(", ")));
        }
        let unpinned: Vec<_> = report.frames.iter().filter(|(frame, outcome)| {
            outcome.included() && self.saved_alert_pin(alert, **frame).is_none()
        }).map(|(frame, _)| format!("#{frame}")).collect();
        if !unpinned.is_empty() {
            details.push(("Not pinned now".into(), unpinned.join(", ")));
        }
        details
    }

    fn describe_alert_evidence(&self, alert: &AlertItem, include_payload: bool) -> (String, Option<String>) {
        let frames = alert.evidence_frame_numbers();
        if frames.is_empty() {
            return ("No packet references".into(), None);
        }
        let scope = self.alert_evidence_scope(alert);
        let (mut decoded, mut captured, mut declared) = (0, 0, 0);
        let slots: Vec<_> = self.local_alert_packets(alert, scope, &frames).into_iter()
            .map(|slot| {
                let packet = slot.and_then(|location| location.get(self));
                let status = packet.map_or(FrameStatus::Missing, frame_status);
                if include_payload && alert.capture_id.is_some()
                    && matches!(status, FrameStatus::Complete | FrameStatus::Truncated)
                    && let Some(header) = packet.and_then(captured_transport_header)
                {
                    decoded += 1;
                    captured += header.captured_payload_length;
                    declared += header.declared_payload_length;
                }
                status
            })
            .collect();
        let unresolved = slots.iter().filter(|&&slot| slot == FrameStatus::Missing).count();
        let invalid = slots.iter().filter(|&&slot| slot == FrameStatus::Unreadable).count();
        let retained = frames.len() - unresolved - invalid;
        if retained == 0 && invalid == 0 && let Some(reason) = scope.local_mismatch() {
            return (format!("0/{} verified here; {reason}", frames.len()), None);
        }
        let mut status = format!("{retained}/{} retained", frames.len());
        if scope == AlertEvidenceScope::DifferentCapture {
            status.push_str(" in saved case");
        }
        for (kind, label) in [
            (FrameStatus::Truncated, "truncated"),
            (FrameStatus::LengthUnknown, "capture lengths unknown"),
            (FrameStatus::Unreadable, "invalid capture lengths"),
        ] {
            let count = slots.iter().filter(|&&slot| slot == kind).count();
            if count > 0 { status.push_str(&format!("; {count} {label}")); }
        }
        let mut unresolved_counts = [0; 6];
        for (&frame, slot) in frames.iter().zip(slots) {
            if slot != FrameStatus::Missing { continue; }
            let bucket = match self.previous_archive_check(alert, frame) {
                Some(ArchiveLookup::Missing) => 0,
                Some(ArchiveLookup::Invalid) => 1,
                Some(ArchiveLookup::ReadFailed) => 2,
                Some(ArchiveLookup::Available) => 3,
                None if self.packet_archive.is_some() && scope == AlertEvidenceScope::CurrentCapture
                    && self.frame_may_be_local(scope, frame) => 4,
                None => 5,
            };
            unresolved_counts[bucket] += 1;
        }
        for (count, label) in unresolved_counts.into_iter().zip([
            "not found at last archive check", "invalid at last archive check", "failed archive lookup at last check",
            "in archive at last check", "unchecked in archive", "unavailable",
        ]) {
            if count > 0 { status.push_str(&format!("; {count} {label}")); }
        }
        if scope == AlertEvidenceScope::Unscoped {
            status.push_str("; capture ID not recorded");
        }
        let payload = (decoded > 0).then(|| format!(
            "{captured} captured / {declared} declared TCP/UDP bytes across {decoded}/{} cited frames; not a transfer total",
            frames.len(),
        ));
        (status, payload)
    }

    pub(super) fn alert_trigger_context(&self, alert: &AlertItem) -> (String, String) {
        let frame = alert.packet_no;
        if frame == 0 {
            return ("Not recorded".into(), describe_trigger_flow(alert.flow, None));
        }
        let scope = self.alert_evidence_scope(alert);
        let slot = self.local_alert_packets(alert, scope, &[frame]).pop().flatten();
        let packet = slot.and_then(|location| location.get(self));
        let status = packet.map_or(FrameStatus::Missing, frame_status);
        let description = match status {
            FrameStatus::Complete => "retained, complete capture",
            FrameStatus::Truncated => "retained, truncated",
            FrameStatus::LengthUnknown => "retained, capture length unknown",
            FrameStatus::Unreadable => "invalid capture lengths",
            FrameStatus::Missing if scope == AlertEvidenceScope::CurrentCapture
                && self.packet_archive.is_some() && self.frame_may_be_local(scope, frame) => match self.previous_archive_check(alert, frame) {
                    Some(ArchiveLookup::Missing) => "not found at last archive check",
                    Some(ArchiveLookup::Invalid) => "invalid at last archive check",
                    Some(ArchiveLookup::ReadFailed) => "archive read failed at last check",
                    Some(ArchiveLookup::Available) => "in archive at last check",
                    None => "unchecked in archive",
                },
            FrameStatus::Missing => "not retained here",
        };
        let observed = packet.filter(|_| alert.capture_id.is_some()
            && matches!(status, FrameStatus::Complete | FrameStatus::Truncated))
            .and_then(captured_transport_header).as_ref().and_then(AlertFlow::from_captured_header);
        (format!("#{frame}: {description}"), describe_trigger_flow(alert.flow, observed))
    }

    #[cfg(test)]
    pub(super) fn alert_trigger_status(&self, alert: &AlertItem) -> String {
        self.alert_trigger_context(alert).0
    }

    /// Resolve sorted, unique alert references in one pass without opening the archive.
    pub(super) fn local_alert_packets(
        &self, alert: &AlertItem, scope: AlertEvidenceScope, frames: &[u64],
    ) -> Vec<Option<LocalAlertPacket>> {
        let mut locations: Vec<_> = frames.iter().map(|&frame| {
            (self.saved_alert_pin(alert, frame).is_some()
                || (self.frame_may_be_local(scope, frame) && self.worklist.retained_packet(frame).is_some()))
                .then_some(LocalAlertPacket::Pin(frame))
        }).collect();
        let mut missing = locations.iter().filter(|location| location.is_none()).count();
        if missing == 0 || scope.local_mismatch().is_some() {
            return locations;
        }
        for (position, packet) in self.packets.iter().enumerate() {
            if let Ok(index) = frames.binary_search(&packet.no)
                && locations[index].is_none() && self.frame_may_be_local(scope, packet.no)
            {
                locations[index] = Some(LocalAlertPacket::Buffer(position));
                missing -= 1;
                if missing == 0 {
                    break;
                }
            }
        }
        locations
    }
}

fn describe_trigger_flow(recorded: Option<AlertFlow>, observed: Option<AlertFlow>) -> String {
    let tuple = |flow: AlertFlow| {
        let transport = match flow.transport { AlertTransport::Tcp => "TCP", AlertTransport::Udp => "UDP" };
        format!("{transport} {} -> {}", flow.source, flow.destination)
    };
    match (recorded, observed) {
        (Some(recorded), Some(wire)) if recorded == wire => format!("{} (matches retained trigger)", tuple(wire)),
        (Some(recorded), Some(wire)) => format!("Recorded: {}; retained trigger differs: {}", tuple(recorded), tuple(wire)),
        (Some(recorded), None) => format!("{} (recorded, not verified)", tuple(recorded)),
        (None, Some(wire)) => format!("{} (from retained trigger)", tuple(wire)),
        (None, None) => "Not recorded".into(),
    }
}
