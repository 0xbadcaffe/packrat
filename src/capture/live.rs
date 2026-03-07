#[cfg(feature = "real-capture")]
use pcap::Capture;

use std::time::Instant;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;

use crate::capture::CaptureSource;
use crate::net::packet::Packet;
use crate::net::parser::parse_ethernet;

pub struct LiveCapture {
    pub iface: String,
    pub filter: Option<String>,
}

impl CaptureSource for LiveCapture {
    fn run(self, tx: Sender<Packet>) -> JoinHandle<()> {
        // pcap is a blocking API — run it on a dedicated blocking thread.
        tokio::task::spawn_blocking(move || {
            #[cfg(feature = "real-capture")]
            {
                let mut cap = Capture::from_device(self.iface.as_str())
                    .expect("device not found")
                    .promisc(true)
                    .snaplen(65535)
                    .timeout(100)
                    .open()
                    .expect("failed to open device (root / Administrator required)");

                if let Some(ref f) = self.filter {
                    cap.filter(f, true).expect("invalid BPF filter");
                }

                let start = Instant::now();
                let mut counter = 0u64;

                while let Ok(raw) = cap.next_packet() {
                    let ts = start.elapsed().as_secs_f64();
                    let pkt = parse_ethernet(raw.data, counter + 1, ts);
                    counter += 1;
                    if tx.blocking_send(pkt).is_err() {
                        break;
                    }
                }
            }

            #[cfg(not(feature = "real-capture"))]
            {
                let _ = (self, tx);
            }
        })
    }
}
