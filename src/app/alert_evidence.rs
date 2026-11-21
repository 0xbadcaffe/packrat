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
    pub(super) fn alert_evidence_scope(&self, alert: &AlertItem) -> AlertEvidenceScope {
        match alert.capture_id.as_deref() {
            None if self.capture_id.is_some() => AlertEvidenceScope::MissingCaptureId,
            None => AlertEvidenceScope::Unscoped,
            scope if scope == self.capture_id.as_deref() => AlertEvidenceScope::CurrentCapture,
            _ => AlertEvidenceScope::DifferentCapture,
        }
    }

    pub(crate) fn alert_evidence_status(&self, alert: &AlertItem) -> String {
        let frames = alert.evidence_frame_numbers();
        if frames.is_empty() {
            return "No packet references".into();
        }
        let scope = self.alert_evidence_scope(alert);
        if let Some(reason) = scope.local_mismatch() {
            return format!("0/{} verified here; {reason}", frames.len());
        }

        let truncated = |packet: &Packet| packet.capture.as_ref().is_some_and(|meta| meta.truncated());
        let mut slots: Vec<Option<bool>> = frames.iter().map(|&frame| {
            self.worklist.retained_packet(frame).map(truncated)
        }).collect();
        let mut unresolved = slots.iter().filter(|slot| slot.is_none()).count();
        // One pass through the live buffer, with pinned bytes taking precedence.
        if unresolved > 0 {
            for packet in &self.packets {
                if let Ok(index) = frames.binary_search(&packet.no)
                    && slots[index].is_none()
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
        let truncated = slots.iter().filter(|slot| **slot == Some(true)).count();
        let mut status = format!("{retained}/{} retained", frames.len());
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
