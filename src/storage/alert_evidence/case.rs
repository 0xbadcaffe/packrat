use std::path::Path;

use anyhow::{Result, ensure};
use serde::Serialize;

use crate::model::project::{
    MAX_PINNED_BYTES, MAX_PINNED_PACKETS, ProjectSaveMode, ProjectState, SavedInvestigationItem,
    pinned_packet_cost,
};
use crate::storage::project_store;
use crate::tabs::Tab;

use super::{AlertLogs, FrameStatus, PacketArchive, frame_status, latest_alert_in_logs, scoped_frames};

#[derive(Default, Serialize)]
pub struct AlertProjectSummary {
    pub retained_frames: usize,
    pub missing_frames: usize,
    pub unreadable_frames: usize,
    pub omitted_at_limit: usize,
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
    state.investigation_items.push(SavedInvestigationItem::Alert(alert_id));
    let mut summary = AlertProjectSummary::default();
    let mut bytes_left = MAX_PINNED_BYTES;
    let ordered = frames.iter().find(|&&frame| frame == trigger).into_iter()
        .chain(frames.iter().filter(|&&frame| frame != trigger));
    for &frame in ordered {
        match archive.packet_for_capture(capture_id, frame) {
            Ok(Some(packet)) if frame_status(&packet) != FrameStatus::Unreadable => {
                let cost = pinned_packet_cost(&packet);
                if state.pinned_packets.len() == MAX_PINNED_PACKETS || cost > bytes_left {
                    summary.omitted_at_limit += 1;
                    continue;
                }
                bytes_left -= cost;
                state.pinned_packet_scopes.insert(frame, capture_id.to_owned());
                state.pinned_packets.push(packet);
            }
            Ok(None) => summary.missing_frames += 1,
            Ok(Some(_)) | Err(_) => summary.unreadable_frames += 1,
        }
    }
    state.pinned_packets.sort_unstable_by_key(|packet| packet.no);
    state.investigation_items.extend(state.pinned_packets.iter().map(|packet| SavedInvestigationItem::Packet(packet.no)));
    state.active_investigation = Some(state.pinned_packets.binary_search_by_key(&trigger, |packet| packet.no)
        .map_or(usize::from(!state.pinned_packets.is_empty()), |index| index + 1));
    state.investigation_tray_open = true;
    state.active_tab = Tab::Investigate.index();
    summary.retained_frames = state.pinned_packets.len();
    state.metadata.description = Some(format!(
        "Session {session_id}, capture {capture_id}. {} retained, {} missing, {} unreadable, {} over the tray limit.",
        summary.retained_frames, summary.missing_frames, summary.unreadable_frames, summary.omitted_at_limit,
    ));
    state.alert_items.push(alert);
    project_store::create(&state, output)?;
    Ok(summary)
}
