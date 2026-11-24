use serde::Serialize;

use crate::net::packet::Packet;

pub(in crate::storage) fn packet_times(packet: &Packet) -> (Option<f64>, Option<i128>) {
    let capture_ns = packet.capture.as_ref()
        .and_then(|metadata| metadata.timestamp)
        .map(|time| time.nanoseconds());
    // A missing capture timestamp can be represented as zero in legacy packet time.
    let seconds = capture_ns.map(|ns| ns as f64 / 1e9).or_else(|| {
        (packet.timestamp.is_finite() && packet.timestamp != 0.0).then_some(packet.timestamp)
    });
    (seconds, capture_ns)
}

#[derive(Default, Serialize)]
pub(super) struct CitedTiming {
    timestamped_frames: usize,
    missing_timestamp_frames: usize,
    forward_gaps: u32,
    tied_timestamps: usize,
    backwards_timestamps: usize,
    min_forward_gap_secs: Option<f64>,
    max_forward_gap_secs: Option<f64>,
    mean_forward_gap_secs: Option<f64>,
    #[serde(skip)]
    previous_ns: Option<i128>,
    #[serde(skip)]
    forward_gap_total_ns: i128,
}

impl CitedTiming {
    // Observe in frame order; never bridge a cited frame without capture time.
    pub(super) fn observe(&mut self, time_ns: Option<i128>) {
        let previous = std::mem::replace(&mut self.previous_ns, time_ns);
        let Some(time) = time_ns else {
            self.missing_timestamp_frames += 1;
            return;
        };
        self.timestamped_frames += 1;
        let Some(previous) = previous else {
            return;
        };
        let gap = time - previous;
        if gap < 0 {
            self.backwards_timestamps += 1;
        } else if gap == 0 {
            self.tied_timestamps += 1;
        } else {
            let seconds = gap as f64 / 1e9;
            self.forward_gaps += 1;
            self.forward_gap_total_ns += gap;
            self.min_forward_gap_secs = Some(
                self.min_forward_gap_secs
                    .map_or(seconds, |value| value.min(seconds)),
            );
            self.max_forward_gap_secs = Some(
                self.max_forward_gap_secs
                    .map_or(seconds, |value| value.max(seconds)),
            );
            self.mean_forward_gap_secs =
                Some(self.forward_gap_total_ns as f64 / f64::from(self.forward_gaps) / 1e9);
        }
    }
}
