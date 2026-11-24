use super::TRIGGER_TIMESTAMP_TOLERANCE_SECONDS;
use super::{
    AlertFlow, AlertItem, PacketArchive, TriggerFrame, TriggerSnapshot, read_trigger, snapshot,
};

const MAX_RECOVERY: usize = 64;

#[derive(Default, serde::Serialize)]
pub(super) struct CandidateTriggerRecovery {
    eligible_alerts: usize,
    examined_frames: usize,
    recovered_triggers: usize,
    missing_frames: usize,
    header_unavailable_frames: usize,
    timestamp_unavailable_frames: usize,
    disagreed_with_saved_fields: usize,
    read_failed_frames: usize,
    omitted_alerts: usize,
    #[serde(skip)]
    pending: Vec<(AlertItem, Option<AlertFlow>, Option<f64>)>,
}

impl CandidateTriggerRecovery {
    pub(super) fn enqueue(&mut self, alert: AlertItem, flow: Option<AlertFlow>, time: Option<f64>) {
        if alert.packet_no == 0 {
            return;
        }
        self.eligible_alerts += 1;
        if self.pending.len() >= MAX_RECOVERY {
            self.omitted_alerts += 1;
        } else {
            self.pending.push((alert, flow, time));
        }
    }

    pub(super) fn recover(
        &mut self,
        archive: Option<&mut PacketArchive>,
        capture_id: &str,
    ) -> Vec<TriggerSnapshot> {
        let Some(archive) = archive else {
            self.omitted_alerts += self.pending.len();
            self.pending.clear();
            return Vec::new();
        };
        let mut recovered = Vec::new();
        for (alert, saved_flow, saved_time) in self.pending.drain(..) {
            self.examined_frames += 1;
            match read_trigger(archive, capture_id, alert.packet_no) {
                Ok(TriggerFrame::Transport {
                    flow,
                    time: Some(time),
                    ..
                }) => {
                    if saved_flow.is_some_and(|prior| prior != flow)
                        || saved_time.is_some_and(|prior| {
                            (prior - time).abs() > TRIGGER_TIMESTAMP_TOLERANCE_SECONDS
                        })
                    {
                        self.disagreed_with_saved_fields += 1;
                        continue;
                    }
                    self.recovered_triggers += 1;
                    let mut trigger = snapshot(&alert, flow, time);
                    trigger.derived_from_wire = true;
                    recovered.push(trigger);
                }
                Ok(TriggerFrame::Transport { time: None, .. }) => {
                    self.timestamp_unavailable_frames += 1
                }
                Ok(TriggerFrame::HeaderUnavailable) => self.header_unavailable_frames += 1,
                Ok(TriggerFrame::Missing) => self.missing_frames += 1,
                Err(_) => self.read_failed_frames += 1,
            }
        }
        recovered
    }
}
