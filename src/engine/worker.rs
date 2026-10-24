//! Bounded ownership transport for the passive core. No terminal or enforcement.
use super::shared::ReadCore;
use super::snapshot::{AnalysisSnapshot, InspectionSnapshot};
use super::{AnalysisCore, PacketAnalysis};
use crate::net::packet::Packet;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
};
use std::time::Duration;

mod run;

#[derive(Debug, Clone, Copy)]
pub struct WorkerLimits {
    pub input_capacity: usize,
    pub event_capacity: usize,
    pub history_packets: usize,
    pub history_bytes: usize,
}

impl Default for WorkerLimits {
    fn default() -> Self {
        Self {
            input_capacity: 256,
            event_capacity: 256,
            history_packets: 256,
            history_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Debug)]
pub enum SubmitError<T> {
    Full(T),
    Disconnected(T),
    Oversized(T),
}

#[derive(Debug)]
pub enum WorkerEvent {
    Packet {
        generation: u64,
        sequence: u64,
        packet_no: u64,
        live: bool,
        analysis: PacketAnalysis,
    },
    Inspection {
        generation: u64,
        request_id: u64,
        result: Result<InspectionSnapshot, String>,
    },
    Updated {
        generation: u64,
        request_id: u64,
        result: Result<(), String>,
    },
}

enum Command {
    Packet {
        generation: u64,
        sequence: u64,
        live: bool,
        packet: Packet,
    },
    Inspect {
        generation: u64,
        request_id: u64,
        stream_id: String,
    },
    Clear {
        generation: u64,
    },
    Update {
        generation: u64,
        request_id: u64,
        apply: Box<dyn FnOnce(&mut AnalysisCore) -> Result<(), String> + Send>,
    },
}

#[derive(Clone)]
pub struct WorkerMonitor {
    running: Arc<AtomicBool>,
    latest: Arc<Mutex<Arc<AnalysisSnapshot>>>,
    failure: Arc<Mutex<Option<String>>>,
}

impl WorkerMonitor {
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
    pub fn latest(&self) -> Arc<AnalysisSnapshot> {
        Arc::clone(
            &self
                .latest
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
        )
    }
    pub fn failure(&self) -> Option<String> {
        self.failure
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

pub struct AnalysisWorker {
    sender: Option<SyncSender<Command>>,
    events: Receiver<WorkerEvent>,
    thread: Option<std::thread::JoinHandle<Result<(), String>>>,
    core: ReadCore,
    cancel: Arc<AtomicBool>,
    monitor: WorkerMonitor,
    generation: u64,
    sequence: u64,
}

impl AnalysisWorker {
    pub fn spawn(core: AnalysisCore, limits: WorkerLimits) -> Result<Self, String> {
        if limits.input_capacity == 0
            || limits.input_capacity > 4096
            || limits.event_capacity == 0
            || limits.event_capacity > 4096
            || limits.history_packets > 2000
            || limits.history_bytes > 64 * 1024 * 1024
        {
            return Err("Invalid analysis worker resource limits".into());
        }
        let (sender, commands) = mpsc::sync_channel(limits.input_capacity);
        let (output, events) = mpsc::sync_channel(limits.event_capacity);
        let cancel = Arc::new(AtomicBool::new(false));
        let monitor = WorkerMonitor {
            running: Arc::new(AtomicBool::new(true)),
            latest: Arc::new(Mutex::new(Arc::new(AnalysisSnapshot::capture(
                &core, 0, 0, 0, 0,
            )))),
            failure: Arc::new(Mutex::new(None)),
        };
        let worker_monitor = monitor.clone();
        let worker_cancel = Arc::clone(&cancel);
        let core = ReadCore::new(core);
        let worker_core = core.clone();
        let thread = std::thread::Builder::new()
            .name("packrat-analysis".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run::run(
                        worker_core,
                        limits,
                        commands,
                        output,
                        worker_cancel,
                        &worker_monitor,
                    )
                }))
                .unwrap_or_else(|_| {
                    Err("Analysis worker panicked; session state is no longer trustworthy".into())
                });
                if let Err(error) = &result {
                    *worker_monitor
                        .failure
                        .lock()
                        .unwrap_or_else(|error| error.into_inner()) = Some(error.clone());
                }
                worker_monitor.running.store(false, Ordering::Release);
                result
            })
            .map_err(|error| format!("Start analysis worker: {error}"))?;
        Ok(Self {
            sender: Some(sender),
            events,
            thread: Some(thread),
            core,
            cancel,
            monitor,
            generation: 0,
            sequence: 0,
        })
    }

    pub fn monitor(&self) -> WorkerMonitor {
        self.monitor.clone()
    }

    pub fn read_core(&self) -> ReadCore {
        self.core.clone()
    }

    pub fn try_update(
        &self,
        request_id: u64,
        apply: impl FnOnce(&mut AnalysisCore) -> Result<(), String> + Send + 'static,
    ) -> Result<(), String> {
        self.try_command(Command::Update {
            generation: self.generation,
            request_id,
            apply: Box::new(apply),
        })
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Rejected packets remain owned by the caller; queue pressure is not loss.
    pub fn try_packet(&mut self, packet: Packet, live: bool) -> Result<u64, SubmitError<Packet>> {
        if packet.bytes.len() > 1_048_576 {
            return Err(SubmitError::Oversized(packet));
        }
        let sequence = self.sequence + 1;
        let command = Command::Packet {
            generation: self.generation,
            sequence,
            packet,
            live,
        };
        let Some(sender) = &self.sender else {
            let Command::Packet { packet, .. } = command else {
                unreachable!()
            };
            return Err(SubmitError::Disconnected(packet));
        };
        match sender.try_send(command) {
            Ok(()) => {
                self.sequence = sequence;
                Ok(sequence)
            }
            Err(error) => {
                let (full, command) = match error {
                    TrySendError::Full(command) => (true, command),
                    TrySendError::Disconnected(command) => (false, command),
                };
                let Command::Packet { packet, .. } = command else {
                    unreachable!()
                };
                Err(if full {
                    SubmitError::Full(packet)
                } else {
                    SubmitError::Disconnected(packet)
                })
            }
        }
    }

    pub fn try_inspect(&self, request_id: u64, stream_id: String) -> Result<(), String> {
        if stream_id.len() > 4096 {
            return Err("Invalid inspection stream ID length".into());
        }
        self.try_command(Command::Inspect {
            generation: self.generation,
            request_id,
            stream_id,
        })
    }

    pub fn try_clear(&mut self) -> Result<u64, String> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or("Worker generation exhausted")?;
        self.try_command(Command::Clear { generation })?;
        self.generation = generation;
        Ok(generation)
    }

    fn try_command(&self, command: Command) -> Result<(), String> {
        self.sender
            .as_ref()
            .ok_or("Analysis worker input closed")?
            .try_send(command)
            .map_err(|error| match error {
                TrySendError::Full(_) => "Analysis worker queue is full".into(),
                TrySendError::Disconnected(_) => "Analysis worker disconnected".into(),
            })
    }

    pub fn try_event(&self) -> Result<Option<WorkerEvent>, String> {
        match self.events.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(self
                .monitor
                .failure()
                .unwrap_or_else(|| "Analysis worker event stream closed".into())),
        }
    }

    /// Drain accepted work and deliver every remaining event before joining.
    /// Use only during controlled shutdown, not from an interactive UI tick.
    pub fn finish(self, consume: impl FnMut(WorkerEvent)) -> Result<AnalysisCore, String> {
        self.finish_shared(consume)?.into_core()
    }

    pub fn finish_shared(
        mut self,
        mut consume: impl FnMut(WorkerEvent),
    ) -> Result<ReadCore, String> {
        self.sender.take();
        loop {
            match self.events.recv_timeout(Duration::from_millis(20)) {
                Ok(event) => consume(event),
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if self
                        .thread
                        .as_ref()
                        .is_some_and(|thread| thread.is_finished())
                    {
                        break;
                    }
                }
            }
        }
        self.thread
            .take()
            .ok_or("Analysis worker already joined")?
            .join()
            .map_err(|_| "Analysis worker join failed".to_string())??;
        Ok(self.core.clone())
    }
}

impl Drop for AnalysisWorker {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        self.sender.take();
    }
}
