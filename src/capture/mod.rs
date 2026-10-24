use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use crate::net::packet::Packet;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use futures::FutureExt;

pub struct CaptureTask {
    handle: JoinHandle<Result<(), String>>,
    stop: Arc<AtomicBool>,
}

impl CaptureTask {
    pub fn spawn(future: impl std::future::Future<Output = Result<(), String>> + Send + 'static) -> Self {
        Self { handle: tokio::spawn(future), stop: Arc::new(AtomicBool::new(false)) }
    }

    pub fn blocking(work: impl FnOnce(Arc<AtomicBool>) -> Result<(), String> + Send + 'static) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        Self { handle: tokio::task::spawn_blocking(move || work(worker_stop)), stop }
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

/// Anything that can deliver packets onto a channel.
pub trait CaptureSource: Send + 'static {
    fn run(self, tx: Sender<Packet>) -> CaptureTask;
}
