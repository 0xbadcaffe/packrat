//! Deterministic, finite workload for memory and CPU profiling.

use std::time::{Duration, Instant};

use crate::app::App;
use crate::net::packet::Packet;
use crate::sim::scenario;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileSummary {
    pub packets: usize,
    pub retained_packets: usize,
    pub alerts: usize,
    pub elapsed: Duration,
}

/// Exercise the normal packet-ingestion path without starting a terminal or capture task.
pub fn run(packet_count: usize) -> ProfileSummary {
    let templates = benign_templates();
    let mut app = App::new_for_test();
    let started = Instant::now();

    for index in 0..packet_count {
        let mut packet = templates[index % templates.len()].clone();
        packet.no = index as u64 + 1;
        packet.timestamp = index as f64 * 0.001;
        app.inject_packet(packet);
    }

    ProfileSummary {
        packets: packet_count,
        retained_packets: app.packets.len(),
        alerts: app.alert_center.items.len(),
        elapsed: started.elapsed(),
    }
}

fn benign_templates() -> Vec<Packet> {
    let templates: Vec<_> = scenario::build()
        .into_iter()
        .filter(|packet| {
            matches!(
                packet.protocol.as_str(),
                "DNS" | "HTTP" | "ICMP" | "Modbus" | "MQTT" | "NTP"
            ) && packet.src != "203.0.113.7"
                && packet.dst != "203.0.113.7"
                && !packet.info.contains("Authorization")
        })
        .collect();
    assert!(!templates.is_empty(), "profiling workload requires packet templates");
    templates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_is_finite_and_uses_bounded_packet_retention() {
        let summary = run(10_250);
        assert_eq!(summary.packets, 10_250);
        assert_eq!(summary.retained_packets, 10_000);
        assert!(summary.alerts <= 2_000);
    }
}
