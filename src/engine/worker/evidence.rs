use crate::engine::{AnalysisCore, PacketAnalysis};
use crate::net::packet::Packet;
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet, VecDeque};

const MAX_REFERENCES: usize = 512;
const MAX_FRAMES: usize = crate::analysis::alert_center::MAX_ALERT_PACKET_REFS + 3;
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
    let mut alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| {
        alert_ids.contains(&alert.id) && alert.capture_id == core.alert_center.capture_id
    }).collect();
    alerts.sort_unstable_by_key(|alert| Reverse((alert.priority, alert.id)));
    let mut references = HashMap::new();
    let mut trigger_cited = false;
    for alert in alerts {
        let frames = alert.evidence_frame_numbers();
        trigger_cited |= frames.binary_search(&current.no).is_ok();
        for frame in frames.into_iter().rev().filter(|&frame| frame != current.no) {
            if references.len() == MAX_REFERENCES {
                break;
            }
            references.entry(frame).or_insert(alert.priority);
        }
    }
    let trigger = trigger_cited.then_some(current);
    let mut candidates = Vec::new();
    // The worker's copy wins if a detector also retained the same frame.
    for packet in history.iter().rev().chain(&analysis.retained_evidence) {
        if references.is_empty() { break; }
        if let Some(priority) = references.remove(&packet.no) { candidates.push((priority, packet)); }
    }
    candidates.sort_unstable_by_key(|(priority, packet)| Reverse((*priority, packet.no)));
    let mut bytes = 0;
    let mut frames = Vec::new();
    // Apply the same priority whether or not the supporting frame survived in history.
    for packet in trigger.into_iter().chain(candidates.into_iter().map(|(_, packet)| packet)) {
        if packet.bytes.len() > MAX_BYTES - bytes { continue; }
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
