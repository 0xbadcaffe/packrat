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
        if unresolved > 0 {
            if scope == AlertEvidenceScope::CurrentCapture && self.packet_archive.is_some() {
                status.push_str(&format!("; {unresolved} unchecked in archive"));
            } else {
                status.push_str(&format!("; {unresolved} unavailable"));
            }
        }
        if scope == AlertEvidenceScope::Unscoped {
            status.push_str("; capture ID not recorded");
        }
        status
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
