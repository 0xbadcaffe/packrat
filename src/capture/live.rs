#[cfg(feature = "real-capture")]
use pcap::{Active, Capture};

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
                let Ok(mut cap) = open_capture(&self) else {
                    return;
                };

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

#[cfg(feature = "real-capture")]
fn open_capture(source: &LiveCapture) -> Result<Capture<Active>, String> {
    let mut capture = Capture::from_device(source.iface.as_str())
        .map_err(|error| format!("capture device '{}': {error}", source.iface))?
        .promisc(true)
        .snaplen(65535)
        .timeout(100)
        .open()
        .map_err(|error| format!("open capture device '{}': {error}", source.iface))?;
    if let Some(filter) = source.filter.as_deref() {
        capture
            .filter(filter, true)
            .map_err(|error| format!("invalid BPF filter '{filter}': {error}"))?;
    }
    Ok(capture)
}

#[cfg(all(test, feature = "real-capture"))]
mod tests {
    use super::*;

    #[test]
    fn missing_capture_device_returns_an_error_without_panicking() {
        let source = LiveCapture {
            iface: "packrat-device-that-does-not-exist".into(),
            filter: None,
        };
        assert!(open_capture(&source).is_err());
    }
}
