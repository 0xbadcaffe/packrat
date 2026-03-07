use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use crate::net::packet::Packet;

pub mod simulated;

#[cfg(feature = "real-capture")]
pub mod live;

/// Anything that can deliver packets onto a channel.
pub trait CaptureSource: Send + 'static {
    fn run(self, tx: Sender<Packet>) -> JoinHandle<()>;
}
