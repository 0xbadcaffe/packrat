use crate::engine::{AnalysisCore, PacketAnalysis};
use crate::net::packet::Packet;
use std::collections::{HashSet, VecDeque};

const MAX_REFERENCES: usize = 512;
const MAX_FRAMES: usize = 32;
const MAX_BYTES: usize = 256 * 1024;

pub(super) fn alert_frames(
    core: &AnalysisCore,
    analysis: &PacketAnalysis,
    current: &Packet,
    history: &VecDeque<Packet>,
) -> Vec<Packet> {
    if core.alert_center.archive_evidence_rules.is_none() || analysis.alert_pins.is_empty() {
        return Vec::new();
    }
    let alert_ids: HashSet<_> = analysis.alert_pins.iter().copied().collect();
    let mut references = HashSet::new();
    for alert in core.alert_center.items.iter().rev() {
        if !alert_ids.contains(&alert.id) || alert.capture_id != core.alert_center.capture_id {
            continue;
        }
        for frame in alert.evidence_frame_numbers() {
            references.insert(frame);
            if references.len() == MAX_REFERENCES {
                break;
            }
        }
        if references.len() == MAX_REFERENCES {
            break;
        }
    }
    let mut bytes = 0;
    let mut frames = Vec::new();
    // Prefer the trigger and newest supporting frames when the event budget is tight.
    for packet in std::iter::once(current).chain(history.iter().rev()).chain(&analysis.retained_evidence) {
        if !references.remove(&packet.no) || packet.bytes.len() > MAX_BYTES - bytes {
            continue;
        }
        bytes += packet.bytes.len();
        frames.push(packet.clone());
        if frames.len() == MAX_FRAMES {
            break;
        }
    }
    frames.sort_unstable_by_key(|packet| packet.no);
    frames
}

#[cfg(test)]
#[path = "../../../tests/unit/worker_alert_frames_tests.rs"]
mod tests;
