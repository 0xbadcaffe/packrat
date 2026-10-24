use super::*;
use crate::engine::worker::CoreUpdate;

pub(super) enum QueuedWork {
    Packet {
        packet: Packet,
        live: bool,
        restoring: bool,
    },
    Update {
        id: u64,
        label: String,
        apply: CoreUpdate,
    },
}

impl App {
    pub fn start_background_analysis(&mut self) -> Result<(), String> {
        if self.analysis_worker.is_none() {
            self.analysis_worker = Some(AnalysisWorker::spawn_shared(
                self.core.clone(),
                WorkerLimits {
                    event_capacity: 64,
                    ..Default::default()
                },
            )?);
        }
        Ok(())
    }

    pub fn background_analysis_enabled(&self) -> bool {
        self.analysis_worker.is_some()
    }

    pub fn stop_background_analysis(&mut self) -> Result<usize, String> {
        self.abort_capture();
        self.capturing = false;
        let cancelled = self.pending_analysis.len() + self.packet_effects.len();
        self.pending_analysis.clear();
        self.pending_analysis_bytes = 0;
        self.pending_analysis_events.clear();
        self.analysis_updates.clear();
        self.packet_effects.clear();
        if let Some(worker) = self.analysis_worker.take() {
            worker.cancel_and_join(std::time::Duration::from_secs(3))?;
        }
        Ok(cancelled)
    }
    pub fn analysis_backpressured(&self) -> bool {
        !self.pending_analysis.is_empty()
    }

    pub fn analysis_idle(&self) -> bool {
        self.pending_analysis.is_empty()
            && self.pending_analysis_events.is_empty()
            && self.packet_effects.is_empty()
            && self.analysis_updates.is_empty()
            && self.analysis_generation_ready()
    }

    pub(super) fn analysis_generation_ready(&self) -> bool {
        self.analysis_worker
            .as_ref()
            .is_none_or(|worker| worker.monitor().latest().generation == worker.generation())
    }

    pub(super) fn update_core(
        &mut self,
        label: &str,
        apply: impl FnOnce(&mut AnalysisCore) -> Result<(), String> + Send + 'static,
    ) {
        if self.analysis_worker.is_some() {
            if self.pending_analysis.len() >= 101_024 {
                self.set_status("Analysis control queue limit reached");
                return;
            }
            self.analysis_update_id = self.analysis_update_id.wrapping_add(1);
            self.pending_analysis.push_back(QueuedWork::Update {
                id: self.analysis_update_id,
                label: label.into(),
                apply: Box::new(apply),
            });
        } else {
            let core = self.core.clone();
            let result = apply(&mut core.edit());
            match result {
                Ok(()) if !label.is_empty() => self.set_status(label),
                Err(error) => self.set_status(error),
                _ => (),
            }
        }
    }

    pub(super) fn enqueue_offline_packets(
        &mut self,
        packets: Vec<Packet>,
        restoring: bool,
    ) -> Result<(), String> {
        let bytes = packets
            .iter()
            .try_fold(0usize, |total, packet| {
                total.checked_add(packet.bytes.len().saturating_add(512))
            })
            .ok_or("Offline source byte count overflow")?;
        if self.pending_analysis.len().saturating_add(packets.len()) > 100_000
            || self.pending_analysis_bytes.saturating_add(bytes) > 256 * 1024 * 1024
        {
            return Err("Offline source exceeds the pending analysis budget".into());
        }
        self.live_response_eligible = false;
        self.live_response_incidents.clear();
        self.pending_analysis_bytes += bytes;
        self.pending_analysis
            .extend(packets.into_iter().map(|packet| QueuedWork::Packet {
                packet,
                live: false,
                restoring,
            }));
        Ok(())
    }

    pub fn poll_analysis(&mut self) {
        if self.analysis_worker.is_none() {
            return;
        }
        let began = std::time::Instant::now();
        for _ in 0..128 {
            if began.elapsed() >= std::time::Duration::from_millis(4) {
                break;
            }
            let event = if let Some(event) = self.pending_analysis_events.pop_front() {
                Ok(Some(event))
            } else {
                self.analysis_worker.as_ref().unwrap().try_event()
            };
            let event = match event {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(error) => {
                    self.abort_capture();
                    self.capturing = false;
                    self.set_status(error);
                    break;
                }
            };
            if !self.handle_worker_event(event) {
                break;
            }
        }
        for _ in 0..256 {
            if began.elapsed() >= std::time::Duration::from_millis(8) {
                break;
            }
            let Some(work) = self.pending_analysis.pop_front() else {
                break;
            };
            match work {
                QueuedWork::Packet {
                    packet,
                    live,
                    restoring,
                } => {
                    let size = packet.bytes.len().saturating_add(512);
                    match self.try_analyze_packet(packet, live, restoring) {
                        Ok(()) => {
                            self.pending_analysis_bytes =
                                self.pending_analysis_bytes.saturating_sub(size)
                        }
                        Err(SubmitError::Full(packet)) => {
                            self.pending_analysis.push_front(QueuedWork::Packet {
                                packet,
                                live,
                                restoring,
                            });
                            break;
                        }
                        Err(error) => {
                            self.pending_analysis_bytes =
                                self.pending_analysis_bytes.saturating_sub(size);
                            self.reject_analysis_packet(error);
                            break;
                        }
                    }
                }
                QueuedWork::Update { id, label, apply } => {
                    match self
                        .analysis_worker
                        .as_ref()
                        .unwrap()
                        .try_update_boxed(id, apply)
                    {
                        Ok(()) => {
                            self.analysis_updates.insert(id, label);
                        }
                        Err(SubmitError::Full(apply)) => {
                            self.pending_analysis.push_front(QueuedWork::Update {
                                id,
                                label,
                                apply,
                            });
                            break;
                        }
                        Err(_) => {
                            self.set_status("Analysis update cancelled: worker disconnected");
                            break;
                        }
                    }
                }
            }
        }
    }

    fn handle_worker_event(&mut self, event: WorkerEvent) -> bool {
        let generation = self.analysis_worker.as_ref().unwrap().generation();
        match event {
            WorkerEvent::Packet {
                generation: event_generation,
                sequence,
                live,
                analysis,
                packet_no,
            } => {
                let restoring = self.packet_effects.remove(&sequence).unwrap_or(true);
                if event_generation != generation {
                    return true;
                }
                let Some(context) = self.analysis_context(&analysis) else {
                    self.packet_effects.insert(sequence, restoring);
                    self.pending_analysis_events
                        .push_front(WorkerEvent::Packet {
                            generation: event_generation,
                            sequence,
                            live,
                            analysis,
                            packet_no,
                        });
                    return false;
                };
                self.handle_packet_analysis(analysis, context, live, restoring);
            }
            WorkerEvent::Updated {
                generation: event_generation,
                request_id,
                result,
            } => {
                let label = self
                    .analysis_updates
                    .remove(&request_id)
                    .unwrap_or_default();
                if event_generation == generation {
                    match result {
                        Ok(()) if !label.is_empty() => self.set_status(label),
                        Err(error) => self.set_status(error),
                        _ => (),
                    }
                }
            }
            WorkerEvent::Inspection { .. } => (),
        }
        true
    }

    pub(super) fn reject_analysis_packet(&mut self, error: SubmitError<Packet>) {
        let reason = match error {
            SubmitError::Oversized(_) => "packet exceeds byte limit",
            SubmitError::Disconnected(_) => "worker disconnected",
            SubmitError::Full(_) => "queue is full",
        };
        self.abort_capture();
        self.capturing = false;
        self.set_status(format!(
            "Analysis stopped: {reason}; packet was not analyzed"
        ));
    }
}
