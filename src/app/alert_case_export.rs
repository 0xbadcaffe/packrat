use super::App;
use crate::model::project::{MAX_PINNED_BYTES, pinned_packet_cost};
use crate::storage::alert_evidence::{AlertProjectSummary, FrameStatus, frame_status, save_alert_archive_project};
use std::path::PathBuf;
use std::thread::{Builder, JoinHandle};

pub(super) struct PendingAlertCase {
    output: PathBuf,
    worker: JoinHandle<Result<AlertProjectSummary, String>>,
}

impl App {
    pub(crate) fn export_selected_alert_archive_case(&mut self) {
        let output = PathBuf::from(format!("packrat_alert_{:016x}.json", rand::random::<u64>()));
        let message = match self.start_alert_archive_case(output) {
            Ok(()) => "Exporting selected alert's archived evidence".into(),
            Err(error) => format!("Alert case export unavailable: {error}"),
        };
        self.set_status(message);
    }

    pub(super) fn start_alert_archive_case(&mut self, output: PathBuf) -> Result<(), String> {
        if self.alert_case_export.is_some() {
            return Err("another alert case export is still running".into());
        }
        let alert = self.query_core(|core| core.alert_center.selected_item().cloned())
            .ok_or("analysis busy; retry export")?
            .ok_or("no alert selected")?;
        if alert.capture_id.is_none() {
            return Err("selected alert has no capture ID".into());
        }
        let mut archive = self.packet_archive.as_ref().ok_or("no packet archive is attached")?.reader()?;
        let frames = alert.evidence_frame_numbers();
        let slots = self.local_alert_packets(&alert, self.alert_evidence_scope(&alert), &frames);
        let mut bytes_left = MAX_PINNED_BYTES;
        let trigger = frames.binary_search(&alert.packet_no).ok();
        let order = trigger.into_iter().chain((0..frames.len()).filter(|&index| Some(index) != trigger));
        let local = order.filter_map(|index| {
            let packet = slots[index]?.get(self)?;
            let cost = pinned_packet_cost(packet);
            if cost > bytes_left || frame_status(packet) == FrameStatus::Unreadable { return None; }
            bytes_left -= cost;
            Some((frames[index], packet.clone()))
        }).collect();
        let destination = output.clone();
        let worker = Builder::new().name("packrat-alert-case".into()).spawn(move || {
            save_alert_archive_project(&mut archive, &alert, None, &destination, local).map_err(|error| error.to_string())
        }).map_err(|error| format!("could not start export: {error}"))?;
        self.alert_case_export = Some(PendingAlertCase { output, worker });
        Ok(())
    }

    pub(super) fn poll_alert_case_export(&mut self) {
        if !self.alert_case_export.as_ref().is_some_and(|pending| pending.worker.is_finished()) {
            return;
        }
        let Some(PendingAlertCase { output, worker }) = self.alert_case_export.take() else { return };
        let result = worker.join().unwrap_or_else(|_| Err("alert case worker failed".into()));
        self.set_status(match result {
            Ok(summary) => format!(
                "Alert case: {} retained, {} missing, {} unreadable, {} over limit ({} from local evidence). {}",
                summary.retained_frames, summary.missing_frames, summary.unreadable_frames,
                summary.omitted_at_limit, summary.local_fallback_frames, output.display(),
            ),
            Err(error) => format!("Alert case export failed: {error}"),
        });
    }
}
