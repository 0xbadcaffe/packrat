use super::*;
use crate::analysis::alert_center::AlertItem;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AlertEvidenceScope {
    Unscoped,
    CurrentCapture,
    DifferentCapture,
    MissingCaptureId,
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
    pub(super) fn archive_alert_packets(&mut self, alert: &AlertItem, current: Option<&Packet>) {
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
            let packet = current.filter(|packet| packet.no == frame).or_else(|| self.packet_by_no(frame));
            packet.map_or(Ok(()), |packet| archive.record_scoped(capture_id, packet))
        };
        let (trigger, others) = (alert.packet_no, frames.iter().copied().filter(|&n| n != alert.packet_no));
        let trigger = frames.binary_search(&trigger).ok().map(|_| trigger);
        for frame in trigger.into_iter().chain(others) {
            if let Err(error) = queue(frame) {
                archive.pause("alert evidence queue unavailable");
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
        let truncated = |packet: &Packet| packet.capture.as_ref().is_some_and(|meta| meta.truncated());
        let mut slots: Vec<Option<bool>> = frames.iter().map(|&frame| {
            self.saved_alert_pin(alert, frame)
                .or_else(|| {
                    self.frame_may_be_local(scope, frame)
                        .then(|| self.worklist.retained_packet(frame)).flatten()
                })
                .map(truncated)
        }).collect();
        let mut unresolved = slots.iter().filter(|slot| slot.is_none()).count();
        // One pass through the live buffer, with pinned bytes taking precedence.
        if unresolved > 0 && scope.local_mismatch().is_none() {
            for packet in &self.packets {
                if let Ok(index) = frames.binary_search(&packet.no)
                    && slots[index].is_none()
                    && self.frame_may_be_local(scope, packet.no)
                {
                    slots[index] = Some(truncated(packet));
                    unresolved -= 1;
                    if unresolved == 0 {
                        break;
                    }
                }
            }
        }
        let retained = frames.len() - unresolved;
        if retained == 0 && let Some(reason) = scope.local_mismatch() {
            return format!("0/{} verified here; {reason}", frames.len());
        }
        let truncated = slots.iter().filter(|slot| **slot == Some(true)).count();
        let mut status = format!("{retained}/{} retained", frames.len());
        if scope == AlertEvidenceScope::DifferentCapture {
            status.push_str(" in saved case");
        }
        if truncated > 0 {
            status.push_str(&format!("; {truncated} truncated"));
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
}
