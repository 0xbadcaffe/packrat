use super::*;
use crate::storage::alert_jsonl::AlertJsonlWriter;
use std::time::Duration;

pub(super) const ALERT_SAVE_RETRY_INTERVAL: Duration = Duration::from_secs(30);

impl App {
    pub(super) fn toggle_alert_saving(&mut self) {
        if self.offline_review {
            self.set_status("Live alert logging is unavailable in offline review");
            return;
        }
        self.save_alerts = !self.save_alerts;
        self.alert_save_error_reported = None;
        self.alert_save_next_retry = None;
        if self.save_alerts {
            self.set_status("Enabling alert saving");
            self.poll_alert_saving(Instant::now());
        } else {
            self.configure_core(|core| {
                core.alert_jsonl_writer = None;
                core.alert_save_error = None;
                core.alert_write_backlog.clear();
                core.alert_center.drain_pending_exports();
            });
            self.set_status("Alert saving disabled");
        }
    }

    pub(super) fn poll_alert_saving(&mut self, now: Instant) {
        self.poll_alert_saving_with(now, AlertJsonlWriter::open_default_for_session);
    }

    fn poll_alert_saving_with(
        &mut self,
        now: Instant,
        open: impl FnOnce(&str) -> Result<AlertJsonlWriter, String> + Send + 'static,
    ) {
        if !self.save_alerts {
            return;
        }
        let Some((saving, error)) = self.query_core(|core| {
            (
                core.alert_jsonl_writer.is_some(),
                core.alert_save_error.clone(),
            )
        }) else {
            return;
        };
        if saving {
            if self.alert_save_error_reported.take().is_some() {
                self.set_status("Alert saving restored; retained alerts backfilled");
            }
            self.alert_save_next_retry = None;
            return;
        }
        if let Some(error) = error
            && self.alert_save_error_reported.as_ref() != Some(&error)
        {
            self.set_status(format!("Alert saving unavailable; will retry: {error}"));
            self.alert_save_error_reported = Some(error);
        }
        if self
            .alert_save_next_retry
            .is_some_and(|deadline| now < deadline)
        {
            return;
        }
        self.alert_save_next_retry = Some(now + ALERT_SAVE_RETRY_INTERVAL);
        let session = self.alert_session_id.clone();
        self.configure_core(move |core| {
            if core.alert_jsonl_writer.is_some() {
                return;
            }
            core.alert_write_backlog.extend(core.alert_center.drain_pending_exports());
            match open(&session).and_then(|mut writer| {
                writer.backfill_snapshots(core.alert_write_backlog.iter().chain(&core.alert_center.items))?;
                Ok(writer)
            }) {
                Ok(writer) => {
                    core.alert_jsonl_writer = Some(std::sync::Arc::new(std::sync::Mutex::new(writer)));
                    core.alert_save_error = None;
                    core.alert_write_backlog.clear();
                }
                Err(error) => core.record_alert_save_failure(error),
            }
        });
    }
}

#[cfg(test)]
#[path = "../../tests/unit/app_alert_saving_tests.rs"]
mod tests;
