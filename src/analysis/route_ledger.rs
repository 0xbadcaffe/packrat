//! Learned outbound-route policy and drift findings.

use std::collections::HashSet;
use std::path::PathBuf;

use crate::net::packet::Packet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMode {
    Observe,
    Learn,
    Enforce,
}

impl std::fmt::Display for RouteMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Observe => write!(f, "observe"),
            Self::Learn => write!(f, "learn"),
            Self::Enforce => write!(f, "detect drift"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RouteProfile {
    pub subject: String,
    pub target: String,
    pub port: u16,
    pub protocol: String,
    pub authority: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RouteDrift {
    pub packet_no: u64,
    pub timestamp: f64,
    pub route: RouteProfile,
}

#[derive(Debug)]
pub struct RouteLedger {
    pub mode: RouteMode,
    pub baseline: HashSet<RouteProfile>,
    pub observed: HashSet<RouteProfile>,
    pub drift: Vec<RouteDrift>,
    pub baseline_path: PathBuf,
}

impl Default for RouteLedger {
    fn default() -> Self {
        let baseline_path = dirs_next::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("packrat")
            .join("route-baseline.json");
        let mut ledger = Self {
            mode: RouteMode::Observe,
            baseline: HashSet::new(),
            observed: HashSet::new(),
            drift: Vec::new(),
            baseline_path,
        };
        let _ = ledger.load();
        ledger
    }
}

impl RouteLedger {
    pub fn observe(&mut self, packet: &Packet, process: Option<&str>) {
        let Some(port) = packet.dst_port else { return; };
        if packet.dst.is_empty() || packet.dst == "0.0.0.0" { return; }
        let route = RouteProfile {
            subject: process.unwrap_or(&packet.src).to_string(),
            target: packet.dst.clone(),
            port,
            protocol: packet.protocol.clone(),
            authority: extract_authority(&packet.info),
        };
        match self.mode {
            RouteMode::Observe => { self.observed.insert(route); }
            RouteMode::Learn => {
                self.observed.insert(route.clone());
                self.baseline.insert(route);
            }
            RouteMode::Enforce => {
                self.observed.insert(route.clone());
                if !self.baseline.contains(&route)
                    && self.drift.last().is_none_or(|last| last.packet_no != packet.no)
                {
                    if self.drift.len() >= 1_000 { self.drift.remove(0); }
                    self.drift.push(RouteDrift {
                        packet_no: packet.no,
                        timestamp: packet.timestamp,
                        route,
                    });
                }
            }
        }
    }

    pub fn cycle_mode(&mut self) -> Result<RouteMode, String> {
        self.mode = match self.mode {
            RouteMode::Observe => RouteMode::Learn,
            RouteMode::Learn => {
                self.save()?;
                RouteMode::Enforce
            }
            RouteMode::Enforce => RouteMode::Observe,
        };
        Ok(self.mode)
    }

    pub fn promote_observed(&mut self) -> Result<usize, String> {
        let before = self.baseline.len();
        self.baseline.extend(self.observed.iter().cloned());
        self.save()?;
        Ok(self.baseline.len() - before)
    }

    pub fn save(&self) -> Result<(), String> {
        if let Some(parent) = self.baseline_path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| format!("create route policy directory: {error}"))?;
        }
        let mut routes: Vec<_> = self.baseline.iter().collect();
        routes.sort_by(|left, right| (&left.subject, &left.target, left.port).cmp(&(&right.subject, &right.target, right.port)));
        let json = serde_json::to_string_pretty(&routes).map_err(|error| format!("serialize route policy: {error}"))?;
        std::fs::write(&self.baseline_path, json).map_err(|error| format!("write route policy: {error}"))
    }

    pub fn load(&mut self) -> Result<usize, String> {
        if !self.baseline_path.exists() { return Ok(0); }
        let text = std::fs::read_to_string(&self.baseline_path).map_err(|error| format!("read route policy: {error}"))?;
        let routes: Vec<RouteProfile> = serde_json::from_str(&text).map_err(|error| format!("parse route policy: {error}"))?;
        self.baseline = routes.into_iter().collect();
        Ok(self.baseline.len())
    }

    pub fn clear_session(&mut self) {
        self.observed.clear();
        self.drift.clear();
    }
}

fn extract_authority(info: &str) -> Option<String> {
    for marker in ["SNI=", "Host: ", "Query "] {
        if let Some(value) = info.split(marker).nth(1).and_then(|value| value.split_whitespace().next()) {
            let value = value.trim_matches(|ch: char| ch == ',' || ch == ';');
            if !value.is_empty() { return Some(value.to_ascii_lowercase()); }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(no: u64, target: &str) -> Packet {
        Packet {
            no,
            timestamp: no as f64,
            src: "10.0.0.5".into(),
            dst: target.into(),
            protocol: "TLS".into(),
            length: 100,
            info: "Client Hello SNI=api.example.test".into(),
            src_port: Some(50000),
            dst_port: Some(443),
            vlan_id: None,
            vlan_pcp: None,
            vlan_dei: None,
            outer_vlan_id: None,
            bytes: Vec::new(),
        }
    }

    #[test]
    fn learns_then_detects_route_drift() {
        let mut ledger = RouteLedger {
            baseline_path: std::env::temp_dir().join(format!("packrat-route-test-{}.json", std::process::id())),
            ..Default::default()
        };
        ledger.mode = RouteMode::Learn;
        ledger.observe(&packet(1, "203.0.113.10"), Some("agent"));
        ledger.mode = RouteMode::Enforce;
        ledger.observe(&packet(2, "203.0.113.10"), Some("agent"));
        ledger.observe(&packet(3, "198.51.100.44"), Some("agent"));
        assert_eq!(ledger.drift.len(), 1);
        assert_eq!(ledger.drift[0].route.target, "198.51.100.44");
        let _ = std::fs::remove_file(&ledger.baseline_path);
    }
}
