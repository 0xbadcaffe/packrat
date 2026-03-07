use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;

use crate::capture::CaptureSource;
use crate::sim::generator::generate_packet;
use crate::net::packet::Packet;

pub struct SimulatedCapture;

impl CaptureSource for SimulatedCapture {
    fn run(self, tx: Sender<Packet>) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            let mut counter = 0u64;
            loop {
                interval.tick().await;
                let burst = (rand::random::<u8>() % 4) as u64 + 1;
                for _ in 0..burst {
                    let pkt = generate_packet(counter);
                    counter += 1;
                    if tx.send(pkt).await.is_err() {
                        return;
                    }
                }
            }
        })
    }
}
