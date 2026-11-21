use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use crate::net::packet::Packet;
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use futures::FutureExt;

pub struct CaptureTask {
    handle: JoinHandle<Result<(), String>>,
    stop: Arc<AtomicBool>,
    loss: Arc<CaptureLoss>,
    run_id: u64,
}

pub(crate) struct CaptureLoss(AtomicU64);

impl Default for CaptureLoss {
    fn default() -> Self {
        Self(AtomicU64::new(u64::MAX))
    }
}

impl CaptureLoss {
    #[cfg(any(feature = "real-capture", test))]
    pub(crate) fn publish(&self, dropped: Option<u32>) {
        self.0.store(dropped.map_or(u64::MAX, u64::from), Ordering::Relaxed);
    }

    fn dropped(&self) -> Option<u32> {
        u32::try_from(self.0.load(Ordering::Relaxed)).ok()
    }
}

impl CaptureTask {
    pub fn spawn(future: impl std::future::Future<Output = Result<(), String>> + Send + 'static) -> Self {
        Self {
            handle: tokio::spawn(future),
            stop: Arc::new(AtomicBool::new(false)),
            loss: Arc::new(CaptureLoss::default()),
            run_id: rand::random(),
        }
    }

    pub fn blocking(work: impl FnOnce(Arc<AtomicBool>) -> Result<(), String> + Send + 'static) -> Self {
        Self::blocking_with_loss(move |stop, _| work(stop))
    }

    pub(crate) fn blocking_with_loss(
        work: impl FnOnce(Arc<AtomicBool>, Arc<CaptureLoss>) -> Result<(), String> + Send + 'static,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let loss = Arc::new(CaptureLoss::default());
        let worker_loss = loss.clone();
        Self {
            handle: tokio::task::spawn_blocking(move || work(worker_stop, worker_loss)),
            stop,
            loss,
            run_id: rand::random(),
        }
    }

    pub(crate) fn run_id(&self) -> u64 {
        self.run_id
    }

    pub fn pcap_buffer_drops(&self) -> Option<u32> {
        self.loss.dropped()
    }

    pub fn result(&mut self) -> Option<Result<(), String>> {
        (&mut self.handle).now_or_never().map(|result| result.unwrap_or_else(|error| Err(format!("Capture worker failed: {error}"))))
    }

    pub fn abort(&self) {
        self.stop.store(true, Ordering::Release);
        self.handle.abort();
    }
}

impl Drop for CaptureTask {
    fn drop(&mut self) { self.abort(); }
}

#[cfg(feature = "real-capture")]
pub mod live;
pub mod helper;
pub mod pcapng;
pub mod dispatch;

/// Anything that can deliver packets onto a channel.
pub trait CaptureSource: Send + 'static {
    fn run(self, tx: Sender<Packet>) -> CaptureTask;
}

#[cfg(test)]
#[path = "../../tests/unit/capture_loss_tests.rs"]
mod tests;
