use std::collections::HashMap;

use super::{AlertFlow, PacketArchive, RelatedAlert, Serialize, TriggerFrame, TriggerSnapshot, WINDOW_SECONDS, read_trigger};
use crate::analysis::alert_center::MAX_ALERT_PACKET_REFS;

#[derive(Default, Serialize)]
pub(super) struct CitedFlowSearch {
    frames_examined: usize,
    usable_frames: usize,
    missing_frames: usize,
    header_unavailable_frames: usize,
    timestamp_unavailable_frames: usize,
    read_failed_frames: usize,
    omitted_frames: usize,
    directional_flows: usize,
    #[serde(skip)]
    by_flow: HashMap<AlertFlow, Vec<(u64, f64)>>,
}

#[derive(Serialize)]
pub(super) struct CitedFrameMatch {
    frame_number: u64,
    pub(super) seconds_from_frame: f64,
}

impl CitedFlowSearch {
    pub(super) fn read(archive: &mut PacketArchive, capture: &str, frames: &[u64]) -> Self {
        let skipped = frames.len().saturating_sub(MAX_ALERT_PACKET_REFS + 3);
        let mut result = Self { omitted_frames: skipped, ..Self::default() };
        for &frame in &frames[skipped..] {
            result.frames_examined += 1;
            match read_trigger(archive, capture, frame) {
                Ok(TriggerFrame::Missing) => result.missing_frames += 1,
                Ok(TriggerFrame::HeaderUnavailable) => result.header_unavailable_frames += 1,
                Ok(TriggerFrame::Transport { time: None, .. }) => result.timestamp_unavailable_frames += 1,
                Ok(TriggerFrame::Transport { flow, time: Some(time) }) => {
                    result.usable_frames += 1;
                    result.by_flow.entry(flow).or_default().push((frame, time));
                }
                Err(_) => result.read_failed_frames += 1,
            }
        }
        result.directional_flows = result.by_flow.len();
        result
    }

    pub(super) fn has_flows(&self) -> bool { !self.by_flow.is_empty() }

    pub(super) fn classify(&self, snapshot: TriggerSnapshot) -> Option<RelatedAlert> {
        let flow = snapshot.flow;
        let reverse = AlertFlow { source: flow.destination, destination: flow.source, ..flow };
        let (frame_number, seconds_from_frame, direction) = [(flow, "same"), (reverse, "reverse")]
            .into_iter().flat_map(|(key, direction)| {
                self.by_flow.get(&key).into_iter().flatten().filter_map(move |&(frame, time)| {
                    let delta = snapshot.time - time;
                    (delta.abs() <= WINDOW_SECONDS as f64).then_some((frame, delta, direction))
                })
            })
            .min_by(|left, right| left.1.abs().total_cmp(&right.1.abs()).then(left.0.cmp(&right.0)))?;
        Some(RelatedAlert {
            snapshot, seconds_from_anchor_trigger: None, direction, trigger_evidence: None,
            matched_cited_frame: Some(CitedFrameMatch { frame_number, seconds_from_frame }),
        })
    }
}
