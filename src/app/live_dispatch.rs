use super::*;
use crate::capture::dispatch::DispatchBudget;

impl App {
    pub fn dispatch_capture(
        &mut self,
        receiver: &mut tokio::sync::mpsc::Receiver<Packet>,
        pending: &mut Option<Packet>,
    ) -> Result<(), String> {
        let submit = |app: &mut App, packet: Packet, pending: &mut Option<Packet>| match app
            .try_ingest_packet(packet)
        {
            Ok(()) => Ok(true),
            Err(SubmitError::Full(packet)) => {
                *pending = Some(packet);
                Ok(false)
            }
            Err(SubmitError::Oversized(_)) => {
                Err("Capture packet exceeds the analysis byte limit".to_string())
            }
            Err(SubmitError::Disconnected(_)) => {
                Err("Analysis worker disconnected; capture dispatch stopped".to_string())
            }
        };
        if let Some(packet) = pending.take() {
            if !submit(self, packet, pending)? {
                return Ok(());
            }
        }
        if self.analysis_backpressured() {
            return Ok(());
        }
        let mut error = None;
        DispatchBudget::default().drain_while(receiver, |packet| {
            match submit(self, packet, pending) {
                Ok(ready) => ready,
                Err(reason) => {
                    error = Some(reason);
                    false
                }
            }
        });
        error.map_or(Ok(()), Err)
    }
}
