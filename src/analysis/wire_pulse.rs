//! Passive DNS and TCP handshake latency measurements.

use std::collections::HashMap;

use crate::net::packet::Packet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PulseKind {
    Dns,
    TcpHandshake,
    Gateway,
}

impl std::fmt::Display for PulseKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dns => write!(f, "DNS"),
            Self::TcpHandshake => write!(f, "TCP"),
            Self::Gateway => write!(f, "Gateway"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PulseSample {
    pub kind: PulseKind,
    pub target: String,
    pub latency_ms: f64,
    pub packet_no: u64,
    pub timestamp: f64,
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct DnsKey {
    client: String,
    server: String,
    transaction: u16,
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct SynKey {
    client: String,
    server: String,
    client_port: u16,
    server_port: u16,
}

#[derive(Debug, Default)]
pub struct WirePulse {
    pub samples: Vec<PulseSample>,
    pub gateway: Option<String>,
    pending_dns: HashMap<DnsKey, f64>,
    pending_syn: HashMap<SynKey, f64>,
}

impl WirePulse {
    pub fn observe(&mut self, packet: &Packet) {
        if self.gateway.is_none() {
            self.gateway = default_gateway();
        }
        self.observe_dns(packet);
        self.observe_tcp(packet);
        self.prune(packet.timestamp);
    }

    pub fn median_ms(&self) -> Option<f64> {
        percentile(&self.samples, 0.5)
    }

    pub fn p95_ms(&self) -> Option<f64> {
        percentile(&self.samples, 0.95)
    }

    pub fn histogram(&self) -> [usize; 6] {
        let mut buckets = [0; 6];
        for sample in &self.samples {
            let index = match sample.latency_ms {
                value if value < 1.0 => 0,
                value if value < 10.0 => 1,
                value if value < 50.0 => 2,
                value if value < 100.0 => 3,
                value if value < 250.0 => 4,
                _ => 5,
            };
            buckets[index] += 1;
        }
        buckets
    }

    pub fn clear(&mut self) {
        self.samples.clear();
        self.pending_dns.clear();
        self.pending_syn.clear();
    }

    fn observe_dns(&mut self, packet: &Packet) {
        if packet.src_port != Some(53) && packet.dst_port != Some(53) { return; }
        let Some(payload) = transport_payload(&packet.bytes, 17) else { return; };
        if payload.len() < 12 { return; }
        let transaction = u16::from_be_bytes([payload[0], payload[1]]);
        let response = payload[2] & 0x80 != 0;
        if !response && packet.dst_port == Some(53) {
            self.pending_dns.insert(DnsKey {
                client: packet.src.clone(),
                server: packet.dst.clone(),
                transaction,
            }, packet.timestamp);
        } else if response && packet.src_port == Some(53) {
            let key = DnsKey {
                client: packet.dst.clone(),
                server: packet.src.clone(),
                transaction,
            };
            if let Some(start) = self.pending_dns.remove(&key) {
                self.push(PulseSample {
                    kind: PulseKind::Dns,
                    target: packet.src.clone(),
                    latency_ms: (packet.timestamp - start).max(0.0) * 1_000.0,
                    packet_no: packet.no,
                    timestamp: packet.timestamp,
                });
            }
        }
    }

    fn observe_tcp(&mut self, packet: &Packet) {
        let Some(flags) = tcp_flags(&packet.bytes) else { return; };
        let syn = flags & 0x02 != 0;
        let ack = flags & 0x10 != 0;
        let (Some(source_port), Some(target_port)) = (packet.src_port, packet.dst_port) else { return; };
        if syn && !ack {
            self.pending_syn.insert(SynKey {
                client: packet.src.clone(),
                server: packet.dst.clone(),
                client_port: source_port,
                server_port: target_port,
            }, packet.timestamp);
        } else if syn && ack {
            let key = SynKey {
                client: packet.dst.clone(),
                server: packet.src.clone(),
                client_port: target_port,
                server_port: source_port,
            };
            if let Some(start) = self.pending_syn.remove(&key) {
                let kind = if self.gateway.as_deref() == Some(packet.src.as_str()) {
                    PulseKind::Gateway
                } else {
                    PulseKind::TcpHandshake
                };
                self.push(PulseSample {
                    kind,
                    target: packet.src.clone(),
                    latency_ms: (packet.timestamp - start).max(0.0) * 1_000.0,
                    packet_no: packet.no,
                    timestamp: packet.timestamp,
                });
            }
        }
    }

    fn push(&mut self, sample: PulseSample) {
        if self.samples.len() >= 2_000 { self.samples.remove(0); }
        self.samples.push(sample);
    }

    fn prune(&mut self, now: f64) {
        self.pending_dns.retain(|_, timestamp| now - *timestamp <= 30.0);
        self.pending_syn.retain(|_, timestamp| now - *timestamp <= 30.0);
    }
}

fn percentile(samples: &[PulseSample], fraction: f64) -> Option<f64> {
    if samples.is_empty() { return None; }
    let mut values: Vec<_> = samples.iter().map(|sample| sample.latency_ms).collect();
    values.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let index = ((values.len() - 1) as f64 * fraction).round() as usize;
    values.get(index).copied()
}

fn tcp_flags(raw: &[u8]) -> Option<u8> {
    let transport = transport_offset(raw, 6)?;
    raw.get(transport + 13).copied()
}

fn transport_payload(raw: &[u8], protocol: u8) -> Option<&[u8]> {
    let transport = transport_offset(raw, protocol)?;
    let header = if protocol == 17 {
        8
    } else {
        ((*raw.get(transport + 12)? >> 4) as usize) * 4
    };
    raw.get(transport + header..)
}

fn transport_offset(raw: &[u8], protocol: u8) -> Option<usize> {
    if raw.len() < 14 { return None; }
    let mut network = 14;
    let mut ether_type = u16::from_be_bytes([raw[12], raw[13]]);
    while matches!(ether_type, 0x8100 | 0x88a8) {
        ether_type = u16::from_be_bytes([*raw.get(network + 2)?, *raw.get(network + 3)?]);
        network += 4;
    }
    match ether_type {
        0x0800 if raw.get(network + 9) == Some(&protocol) => {
            Some(network + ((raw[network] & 0x0f) as usize) * 4)
        }
        0x86dd if raw.get(network + 6) == Some(&protocol) => Some(network + 40),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn default_gateway() -> Option<String> {
    let routes = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in routes.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.get(1) == Some(&"00000000") {
            let value = u32::from_str_radix(fields.get(2)?, 16).ok()?;
            return Some(std::net::Ipv4Addr::from(value.to_le_bytes()).to_string());
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn default_gateway() -> Option<String> { None }

#[cfg(test)]
#[path = "../../tests/unit/analysis_wire_pulse_tests.rs"]
mod tests;
