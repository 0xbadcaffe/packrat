#[cfg(feature = "real-capture")]
use pcap::{Active, Capture};

use std::sync::atomic::Ordering;
use tokio::sync::mpsc::Sender;

use crate::capture::{CaptureSource, CaptureTask};
use crate::net::packet::{Packet, CaptureMetadata, CaptureTimestamp, TimestampResolution};
use crate::net::parser::parse_captured;

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
                let link_type = u32::try_from(cap.get_datalink().0).map_err(|_| "Invalid capture link type")?;
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
                    if !(0..1_000_000).contains(&raw.header.ts.tv_usec) || raw.header.len < raw.header.caplen {
                        return Err("Invalid capture timestamp or packet length".into());
                    }
                    let metadata = CaptureMetadata {
                        timestamp: Some(CaptureTimestamp {
                            ticks: raw.header.ts.tv_usec as u64,
                            resolution: TimestampResolution::Decimal(6),
                            offset_seconds: raw.header.ts.tv_sec as i64,
                        }),
                        captured_length: raw.header.caplen,
                        wire_length: raw.header.len,
                        link_type,
                        interface_id: 0,
                        section_id: 0,
                        interface_name: Some(self.iface.clone()),
                        comments: Vec::new(),
                    };
                    let mut pkt = parse_captured(raw.data, counter + 1, metadata)?;
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
#[path = "../../tests/unit/capture_live_tests.rs"]
mod tests;
