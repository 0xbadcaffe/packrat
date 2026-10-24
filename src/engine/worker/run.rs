use super::*;
use crate::engine::PacketDisposition;
use std::collections::VecDeque;

pub(super) fn run(
    shared: ReadCore,
    limits: WorkerLimits,
    commands: Receiver<Command>,
    output: SyncSender<WorkerEvent>,
    cancel: Arc<AtomicBool>,
    monitor: &WorkerMonitor,
) -> Result<(), String> {
    let mut history = VecDeque::<Packet>::new();
    let mut history_bytes = 0usize;
    let mut generation = 0;
    let mut sequence = 0;
    let mut analyzed = 0;
    let mut skipped = 0;
    let mut dirty = false;
    let mut response_eligible = true;
    loop {
        if cancel.load(Ordering::Acquire) {
            break;
        }
        let command = match commands.recv_timeout(Duration::from_millis(20)) {
            Ok(command) => command,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if dirty {
                    let core = shared.0.lock().map_err(|_| "Analysis state poisoned")?;
                    publish(&core, monitor, generation, sequence, analyzed, skipped);
                    dirty = false;
                }
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        let mut core = shared.0.lock().map_err(|_| "Analysis state poisoned")?;
        let event = match command {
            Command::Packet {
                generation: submitted,
                sequence: number,
                packet,
                live,
            } => {
                if submitted != generation {
                    return Err("Packet crossed an analysis generation boundary".into());
                }
                response_eligible &= live;
                let analysis = core.analyze_with_history(&packet, history.iter().cloned());
                if analysis.disposition == PacketDisposition::Analyzed {
                    analyzed += 1;
                } else {
                    skipped += 1;
                }
                sequence = number;
                let packet_no = packet.no;
                if analysis.disposition == PacketDisposition::Analyzed {
                    history_bytes += packet.bytes.len();
                    history.push_back(packet);
                }
                while history.len() > limits.history_packets || history_bytes > limits.history_bytes
                {
                    if let Some(packet) = history.pop_front() {
                        history_bytes -= packet.bytes.len();
                    } else {
                        break;
                    }
                }
                dirty = true;
                WorkerEvent::Packet {
                    generation,
                    sequence,
                    packet_no,
                    live: live && response_eligible,
                    analysis,
                }
            }
            Command::Inspect {
                generation: submitted,
                request_id,
                stream_id,
            } => {
                let result = if submitted == generation {
                    core.inspection_snapshot(&stream_id, generation, sequence)
                        .ok_or_else(|| "Requested stream is no longer retained".into())
                } else {
                    Err("Inspection belongs to an expired generation".into())
                };
                WorkerEvent::Inspection {
                    generation,
                    request_id,
                    result,
                }
            }
            Command::Clear { generation: next } => {
                if next != generation + 1 {
                    return Err("Invalid analysis clear generation".into());
                }
                generation = next;
                core.clear();
                history.clear();
                history_bytes = 0;
                analyzed = 0;
                skipped = 0;
                response_eligible = true;
                publish(&core, monitor, generation, sequence, analyzed, skipped);
                dirty = false;
                continue;
            }
            Command::Update {
                generation: submitted,
                request_id,
                apply,
            } => {
                let result = if submitted == generation {
                    apply(&mut core)
                } else {
                    Err("Update belongs to an expired generation".into())
                };
                dirty = true;
                WorkerEvent::Updated {
                    generation,
                    request_id,
                    result,
                }
            }
        };
        if dirty && sequence % 32 == 0 {
            publish(&core, monitor, generation, sequence, analyzed, skipped);
            dirty = false;
        }
        drop(core);
        if !send(&output, event, &cancel) {
            break;
        }
    }
    let core = shared.0.lock().map_err(|_| "Analysis state poisoned")?;
    publish(&core, monitor, generation, sequence, analyzed, skipped);
    Ok(())
}

fn publish(
    core: &AnalysisCore,
    monitor: &WorkerMonitor,
    generation: u64,
    sequence: u64,
    analyzed: u64,
    skipped: u64,
) {
    let snapshot = Arc::new(AnalysisSnapshot::capture(
        core, generation, sequence, analyzed, skipped,
    ));
    *monitor
        .latest
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = snapshot;
}

fn send(output: &SyncSender<WorkerEvent>, mut event: WorkerEvent, cancel: &AtomicBool) -> bool {
    loop {
        if cancel.load(Ordering::Acquire) {
            return false;
        }
        match output.try_send(event) {
            Ok(()) => return true,
            Err(TrySendError::Disconnected(_)) => return false,
            Err(TrySendError::Full(pending)) => {
                event = pending;
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}
