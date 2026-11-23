use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use crate::net::packet::Packet;
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use futures::FutureExt;

pub struct CaptureTask {
    handle: JoinHandle<Result<(), String>>,
    stop: Arc<AtomicBool>,
    stats: Arc<CaptureStats>,
    run_id: u64,
}

pub(crate) struct CaptureStats {
    dropped: AtomicU64,
    link_type: AtomicU64,
    truncated_frames: AtomicU64,
    queue_full_packets: AtomicU64,
}

impl Default for CaptureStats {
    fn default() -> Self {
        Self {
            dropped: AtomicU64::new(u64::MAX),
            link_type: AtomicU64::new(u64::MAX),
            truncated_frames: AtomicU64::new(0),
            queue_full_packets: AtomicU64::new(0),
        }
    }
}

impl CaptureStats {
    #[cfg(any(feature = "real-capture", test))]
    pub(crate) fn publish_drops(&self, dropped: Option<u32>) {
        self.dropped.store(dropped.map_or(u64::MAX, u64::from), Ordering::Relaxed);
    }

    #[cfg(any(feature = "real-capture", test))]
    pub(crate) fn publish_link_type(&self, link_type: u32) {
        self.link_type.store(u64::from(link_type), Ordering::Relaxed);
    }

    #[cfg(any(feature = "real-capture", test))]
    pub(crate) fn observe_frame_lengths(&self, captured: u32, wire: u32) -> Result<(), String> {
        if captured > wire {
            return Err("Invalid capture packet length".into());
        }
        if captured < wire {
            self.truncated_frames.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    fn dropped(&self) -> Option<u32> {
        u32::try_from(self.dropped.load(Ordering::Relaxed)).ok()
    }

    #[cfg(feature = "real-capture")]
    pub(crate) fn observe_queue_full(&self) {
        self.queue_full_packets.fetch_add(1, Ordering::Relaxed);
    }
}

impl CaptureTask {
    pub fn spawn(future: impl std::future::Future<Output = Result<(), String>> + Send + 'static) -> Self {
        Self {
            handle: tokio::spawn(future),
            stop: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(CaptureStats::default()),
            run_id: rand::random(),
        }
    }

    pub fn blocking(work: impl FnOnce(Arc<AtomicBool>) -> Result<(), String> + Send + 'static) -> Self {
        Self::blocking_with_stats(move |stop, _| work(stop))
    }

    pub(crate) fn blocking_with_stats(
        work: impl FnOnce(Arc<AtomicBool>, Arc<CaptureStats>) -> Result<(), String> + Send + 'static,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let stats = Arc::new(CaptureStats::default());
        let worker_stats = stats.clone();
        Self {
            handle: tokio::task::spawn_blocking(move || work(worker_stop, worker_stats)),
            stop,
            stats,
            run_id: rand::random(),
        }
    }

    pub(crate) fn run_id(&self) -> u64 {
        self.run_id
    }

    pub fn pcap_buffer_drops(&self) -> Option<u32> {
        self.stats.dropped()
    }

    pub fn link_type(&self) -> Option<u32> {
        u32::try_from(self.stats.link_type.load(Ordering::Relaxed)).ok()
    }

    pub fn truncated_frames(&self) -> Option<u64> {
        self.link_type().map(|_| self.stats.truncated_frames.load(Ordering::Relaxed))
    }

    pub fn queue_full_packets(&self) -> Option<u64> {
        self.link_type().map(|_| self.stats.queue_full_packets.load(Ordering::Relaxed))
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
