//! Cooperative capture dispatch so a busy queue cannot monopolize the UI loop.

use std::num::NonZeroUsize;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Receiver;

#[derive(Debug, Clone, Copy)]
pub struct DispatchBudget {
    packets: NonZeroUsize,
    duration: Duration,
}

impl DispatchBudget {
    /// A zero duration pauses dispatch without removing queued packets.
    pub fn new(packets: NonZeroUsize, duration: Duration) -> Self {
        Self { packets, duration }
    }

    /// Consume ready packets within both bounds, without waiting for a sender.
    /// A single callback may exceed the time budget; it is never interrupted.
    pub fn drain<T>(&self, receiver: &mut Receiver<T>, mut consume: impl FnMut(T)) -> usize {
        self.drain_while(receiver, |packet| {
            consume(packet);
            true
        })
    }

    /// Stop after the callback retains a pending item under downstream pressure.
    /// Items not yet handed to the callback remain in the upstream channel.
    pub fn drain_while<T>(
        &self,
        receiver: &mut Receiver<T>,
        mut consume: impl FnMut(T) -> bool,
    ) -> usize {
        let started = Instant::now();
        let mut count = 0;
        while count < self.packets.get() && started.elapsed() < self.duration {
            let Ok(packet) = receiver.try_recv() else {
                break;
            };
            let ready = consume(packet);
            count += 1;
            if !ready {
                break;
            }
        }
        count
    }
}

impl Default for DispatchBudget {
    fn default() -> Self {
        Self::new(
            NonZeroUsize::new(256).expect("nonzero dispatch budget"),
            Duration::from_millis(8),
        )
    }
}
