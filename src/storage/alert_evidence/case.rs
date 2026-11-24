use std::path::Path;

use anyhow::{Result, ensure};
use serde::Serialize;

use crate::model::project::{
    INVESTIGATE_TAB_INDEX, MAX_PINNED_BYTES, MAX_PINNED_PACKETS, ProjectSaveMode, ProjectState,
    SavedInvestigationItem, pinned_packet_cost,
};
use crate::storage::project_store;

use super::{AlertLogs, FrameStatus, PacketArchive, frame_status, latest_alert_in_logs, scoped_frames};

#[derive(Default, Serialize)]
pub struct AlertProjectSummary {
    pub retained_frames: usize,
    pub truncated_frames: usize,
    pub length_unknown_frames: usize,
    pub missing_frames: usize,
    pub unreadable_frames: usize,
    pub omitted_at_limit: usize,
    trigger_frame: Option<CaseTrigger>,
}

#[derive(Serialize)]
struct CaseTrigger {
    frame_number: u64,
    status: FrameStatus,
    included: bool,
}

pub fn create_alert_project(
    archive: &mut PacketArchive,
    logs: AlertLogs<'_>,
    session_id: &str,
    capture_id: &str,
    alert_id: u64,
    output: &Path,
) -> Result<AlertProjectSummary> {
    ensure!(!session_id.is_empty() && session_id.len() <= 128 && session_id.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')), "Invalid session ID");
    let alert = latest_alert_in_logs(logs, session_id, alert_id, Some(capture_id))?;
    let (capture_id, frames) = scoped_frames(&alert)?;
    let trigger = alert.packet_no;
    let mut state = ProjectState::new(format!("Alert #{alert_id} evidence"), ProjectSaveMode::Lightweight);
    state.investigation_items.push(SavedInvestigationItem::AlertRef {
        id: alert_id, capture_id: Some(capture_id.to_owned()),
    });
    let mut summary = AlertProjectSummary::default();
    let mut bytes_left = MAX_PINNED_BYTES;
    let ordered = frames.iter().find(|&&frame| frame == trigger).into_iter()
        .chain(frames.iter().filter(|&&frame| frame != trigger));
    for &frame in ordered {
        let (status, included) = match archive.packet_for_capture(capture_id, frame) {
            Ok(Some(packet)) => {
                let status = frame_status(&packet);
                let cost = pinned_packet_cost(&packet);
                if status == FrameStatus::Unreadable {
                    summary.unreadable_frames += 1;
                    (status, false)
                } else if state.pinned_packets.len() == MAX_PINNED_PACKETS || cost > bytes_left {
                    summary.omitted_at_limit += 1;
                    (status, false)
                } else {
                    bytes_left -= cost;
                    summary.truncated_frames += usize::from(status == FrameStatus::Truncated);
                    summary.length_unknown_frames += usize::from(status == FrameStatus::LengthUnknown);
                    state.pinned_packet_scopes.insert(frame, capture_id.to_owned());
                    state.pinned_packets.push(packet);
                    (status, true)
                }
            }
            Ok(None) => {
                summary.missing_frames += 1;
                (FrameStatus::Missing, false)
            }
            Err(_) => {
                summary.unreadable_frames += 1;
                (FrameStatus::Unreadable, false)
            }
        };
        if frame == trigger {
            summary.trigger_frame = Some(CaseTrigger { frame_number: frame, status, included });
        }
    }
    state.pinned_packets.sort_unstable_by_key(|packet| packet.no);
    state.investigation_items.extend(state.pinned_packets.iter().map(|packet| SavedInvestigationItem::Packet(packet.no)));
    state.active_investigation = Some(state.pinned_packets.binary_search_by_key(&trigger, |packet| packet.no)
        .map_or(0, |index| index + 1));
    state.investigation_tray_open = true;
    state.active_tab = INVESTIGATE_TAB_INDEX;
    summary.retained_frames = state.pinned_packets.len();
    state.metadata.description = Some(format!(
        "Session {session_id}, capture {capture_id}. {} retained ({} truncated, {} length unknown), {} missing, {} unreadable, {} over the tray limit.{}",
        summary.retained_frames, summary.truncated_frames, summary.length_unknown_frames, summary.missing_frames,
        summary.unreadable_frames, summary.omitted_at_limit,
        summary.trigger_frame.as_ref().filter(|trigger| !trigger.included)
            .map_or_else(String::new, |trigger| format!(" Trigger #{} not included.", trigger.frame_number)),
    ));
    state.alert_items.push(alert);
    project_store::create(&state, output)?;
    Ok(summary)
}
