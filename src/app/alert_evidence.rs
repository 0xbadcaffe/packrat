use super::*;
use crate::analysis::alert_center::AlertItem;
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
        let frames = alert.evidence_frame_numbers();
        if frames.is_empty() {
            return "No packet references".into();
        }
        let scope = self.alert_evidence_scope(alert);
        let slots: Vec<_> = self.local_alert_packets(alert, scope, &frames).into_iter()
            .map(|slot| slot.and_then(|location| location.get(self)).map_or(FrameStatus::Missing, frame_status))
            .collect();
        let unresolved = slots.iter().filter(|&&slot| slot == FrameStatus::Missing).count();
        let invalid = slots.iter().filter(|&&slot| slot == FrameStatus::Unreadable).count();
        let retained = frames.len() - unresolved - invalid;
        if retained == 0 && invalid == 0 && let Some(reason) = scope.local_mismatch() {
            return format!("0/{} verified here; {reason}", frames.len());
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
        status
    }

    pub(super) fn alert_trigger_status(&self, alert: &AlertItem) -> String {
        let frame = alert.packet_no;
        if frame == 0 {
            return "Not recorded".into();
        }
        let scope = self.alert_evidence_scope(alert);
        let slot = self.local_alert_packets(alert, scope, &[frame]).pop().flatten();
        let status = slot.and_then(|location| location.get(self)).map_or(FrameStatus::Missing, frame_status);
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
        format!("#{frame}: {description}")
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
