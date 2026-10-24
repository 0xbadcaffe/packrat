#[cfg(feature = "real-capture")]
use pcap::{Active, Capture};

use std::sync::atomic::Ordering;
use tokio::sync::mpsc::Sender;

use crate::capture::{CaptureSource, CaptureTask};
use crate::net::packet::Packet;
use crate::net::parser::parse_ethernet;

pub struct LiveCapture {
    pub iface: String,
    pub filter: Option<String>,
}

impl CaptureSource for LiveCapture {
    fn run(self, tx: Sender<Packet>) -> CaptureTask {
        // pcap is a blocking API — run it on a dedicated blocking thread.
        CaptureTask::blocking(move |stop| {
            #[cfg(feature = "real-capture")]
            {
                let mut cap = open_capture(&self)?;
                if cap.get_datalink() != pcap::Linktype::ETHERNET {
                    return Err(format!("Unsupported capture link type: {:?}", cap.get_datalink()));
                }
                let mut counter = 0u64;

                while !stop.load(Ordering::Acquire) && !tx.is_closed() {
                    let raw = match cap.next_packet() {
                        Ok(raw) => raw,
                        Err(pcap::Error::TimeoutExpired | pcap::Error::NoMorePackets) => {
                            std::thread::sleep(std::time::Duration::from_millis(2));
                            continue;
                        }
                        Err(error) => return Err(format!("Capture read failed: {error}")),
                    };
                    let ts = raw.header.ts.tv_sec as f64 + raw.header.ts.tv_usec as f64 / 1_000_000.0;
                    let mut pkt = parse_ethernet(raw.data, counter + 1, ts);
                    counter += 1;
                    loop {
                        match tx.try_send(pkt) {
                            Ok(()) => break,
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                            Err(tokio::sync::mpsc::error::TrySendError::Full(pending)) => {
                                if stop.load(Ordering::Acquire) { return Ok(()); }
                                pkt = pending;
                                std::thread::sleep(std::time::Duration::from_millis(1));
                            }
                        }
                    }
                }
            }

            #[cfg(not(feature = "real-capture"))]
            {
                let _ = (self, tx, stop);
            }
            Ok(())
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
    capture.setnonblock().map_err(|error| format!("Set capture nonblocking: {error}"))
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
