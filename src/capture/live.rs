#[cfg(feature = "real-capture")]
use pcap::{Active, Capture};

use std::sync::atomic::Ordering;
use tokio::sync::mpsc::Sender;

use crate::capture::{CaptureStats, CaptureSource, CaptureTask};
use crate::net::packet::{Packet, CaptureMetadata, CaptureTimestamp, TimestampResolution};
use crate::net::parser::parse_captured;

pub struct LiveCapture {
    pub iface: String,
    pub filter: Option<String>,
    pub timeout_ms: u64,
}

impl CaptureSource for LiveCapture {
    fn run(self, tx: Sender<Packet>) -> CaptureTask {
        // pcap is a blocking API — run it on a dedicated blocking thread.
        CaptureTask::blocking_with_stats(move |stop, stats| {
            #[cfg(feature = "real-capture")]
            {
                let mut cap = open_capture(&self)?;
                let link_type = u32::try_from(cap.get_datalink().0).map_err(|_| "Invalid capture link type")?;
                stats.publish_link_type(link_type);
                let mut counter = 0u64;
                let mut next_stats = std::time::Instant::now();

                while !stop.load(Ordering::Acquire) && !tx.is_closed() {
                    sample_drops(&mut cap, &stats, &mut next_stats);
                    let raw = match cap.next_packet() {
                        Ok(raw) => raw,
                        Err(pcap::Error::TimeoutExpired | pcap::Error::NoMorePackets) => {
                            continue;
                        }
                        Err(error) => return Err(format!("Capture read failed: {error}")),
                    };
                    stats.observe_frame_lengths(raw.header.caplen, raw.header.len)?;
                    let metadata = CaptureMetadata {
                        timestamp: Some(pcap_timestamp(
                            raw.header.ts.tv_sec as i64,
                            raw.header.ts.tv_usec as i64,
                        )?),
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
                                sample_drops(&mut cap, &stats, &mut next_stats);
                                std::thread::sleep(std::time::Duration::from_millis(1));
                            }
                        }
                    }
                }
            }

            #[cfg(not(feature = "real-capture"))]
            {
                let _ = (self, tx, stop, stats);
            }
            Ok(())
        })
    }
}

#[cfg(feature = "real-capture")]
fn pcap_timestamp(seconds: i64, micros: i64) -> Result<CaptureTimestamp, String> {
    if !(0..1_000_000).contains(&micros) {
        return Err("Invalid capture timestamp fraction".into());
    }
    // PCAPNG assigns the clock offset to the interface, not each packet.
    let (ticks, offset_seconds) = if let Ok(seconds) = u64::try_from(seconds) {
        let ticks = seconds.checked_mul(1_000_000)
            .and_then(|ticks| ticks.checked_add(micros as u64))
            .ok_or("Capture timestamp exceeds the supported range")?;
        (ticks, 0)
    } else {
        (micros as u64, seconds)
    };
    Ok(CaptureTimestamp {
        ticks,
        resolution: TimestampResolution::Decimal(6),
        offset_seconds,
    })
}

#[cfg(feature = "real-capture")]
fn sample_drops(cap: &mut Capture<Active>, stats: &CaptureStats, next: &mut std::time::Instant) {
    let now = std::time::Instant::now();
    if now >= *next {
        stats.publish_drops(cap.stats().ok().map(|sample| sample.dropped));
        *next = now + std::time::Duration::from_secs(1);
    }
}

#[cfg(feature = "real-capture")]
fn open_capture(source: &LiveCapture) -> Result<Capture<Active>, String> {
    let mut capture = Capture::from_device(source.iface.as_str())
        .map_err(|error| format!("capture device '{}': {error}", source.iface))?
        .promisc(true)
        .snaplen(65535)
        .timeout(source.timeout_ms as i32)
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
#[path = "../../tests/unit/capture_live_tests.rs"]
mod tests;
