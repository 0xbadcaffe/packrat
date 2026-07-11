//! Expiring, audited containment decisions for critical incidents.

use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use crate::analysis::incident::Incident;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatchMode {
    Monitor,
    Preview,
    Manual,
    Automatic,
}

impl std::str::FromStr for LatchMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "monitor" => Ok(Self::Monitor),
            "preview" => Ok(Self::Preview),
            "manual" => Ok(Self::Manual),
            "auto" | "automatic" => Ok(Self::Automatic),
            _ => Err(format!("invalid TrafficLatch mode: {value}")),
        }
    }
}

impl std::fmt::Display for LatchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Monitor => write!(f, "monitor"),
            Self::Preview => write!(f, "preview"),
            Self::Manual => write!(f, "manual"),
            Self::Automatic => write!(f, "automatic"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatchStatus {
    Observed,
    Previewed,
    PendingApproval,
    Applied,
    Rejected,
    Failed,
}

impl std::fmt::Display for LatchStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Self::Observed => "observed",
            Self::Previewed => "previewed",
            Self::PendingApproval => "pending approval",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
        })
    }
}

#[derive(Debug, Clone)]
pub struct LatchAction {
    pub incident_id: u64,
    pub address: Option<IpAddr>,
    pub mode: LatchMode,
    pub status: LatchStatus,
    pub expires_seconds: u64,
    pub detail: String,
    pub created_at: f64,
}

#[derive(Debug, Clone)]
pub struct LatchRequest {
    pub address: IpAddr,
    pub expires_seconds: u64,
}

pub trait LatchBackend {
    fn block(&self, request: &LatchRequest) -> Result<String, String>;
}

#[derive(Debug, Default)]
pub struct NftablesLatch;

impl LatchBackend for NftablesLatch {
    fn block(&self, request: &LatchRequest) -> Result<String, String> {
        #[cfg(target_os = "linux")]
        {
            ensure_nftables_layout()?;
            let (set, family) = match request.address {
                IpAddr::V4(_) => ("blocked_v4", "ip"),
                IpAddr::V6(_) => ("blocked_v6", "ip6"),
            };
            let element = format!("{} timeout {}s", request.address, request.expires_seconds);
            let output = Command::new("nft")
                .args(["add", "element", "inet", "packrat_latch", set, "{", &element, "}"])
                .output()
                .map_err(|error| format!("run nft: {error}"))?;
            if !output.status.success() {
                return Err(format!("nft {family} block failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
            }
            Ok(format!("blocked {} traffic for {} seconds", request.address, request.expires_seconds))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = request;
            Err("TrafficLatch nftables backend is available only on Linux".into())
        }
    }
}

#[cfg(target_os = "linux")]
fn ensure_nftables_layout() -> Result<(), String> {
    let exists = Command::new("nft")
        .args(["list", "table", "inet", "packrat_latch"])
        .output()
        .map_err(|error| format!("run nft: {error}"))?
        .status
        .success();
    if exists { return Ok(()); }

    let layout = r#"table inet packrat_latch {
  set blocked_v4 { type ipv4_addr; flags timeout; }
  set blocked_v6 { type ipv6_addr; flags timeout; }
  chain inbound { type filter hook input priority -10; policy accept; ip saddr @blocked_v4 drop; ip6 saddr @blocked_v6 drop; }
  chain outbound { type filter hook output priority -10; policy accept; ip daddr @blocked_v4 drop; ip6 daddr @blocked_v6 drop; }
  chain transit { type filter hook forward priority -10; policy accept; ip saddr @blocked_v4 drop; ip daddr @blocked_v4 drop; ip6 saddr @blocked_v6 drop; ip6 daddr @blocked_v6 drop; }
}
"#;
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start nft: {error}"))?;
    child.stdin.as_mut().ok_or("nft stdin unavailable")?
        .write_all(layout.as_bytes()).map_err(|error| format!("write nft layout: {error}"))?;
    let output = child.wait_with_output().map_err(|error| format!("wait for nft: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("create nftables layout: {}", String::from_utf8_lossy(&output.stderr).trim()))
    }
}

#[derive(Debug)]
pub struct TrafficLatch {
    pub mode: LatchMode,
    pub expires_seconds: u64,
    pub protected_addresses: Vec<IpAddr>,
    pub actions: Vec<LatchAction>,
}

impl Default for TrafficLatch {
    fn default() -> Self {
        Self {
            mode: LatchMode::Monitor,
            expires_seconds: 900,
            protected_addresses: Vec::new(),
            actions: Vec::new(),
        }
    }
}

impl TrafficLatch {
    pub fn on_incident<B: LatchBackend>(&mut self, incident: &Incident, backend: &B) -> &LatchAction {
        if let Some(index) = self.actions.iter().position(|action| action.incident_id == incident.id) {
            return &self.actions[index];
        }
        let address = incident.attacker.parse::<IpAddr>().ok();
        let (status, detail) = match address {
            None => (LatchStatus::Rejected, "attacker is not a valid IP address".into()),
            Some(address) if !is_blockable(address) => (LatchStatus::Rejected, "special-purpose address is protected".into()),
            Some(address) if self.protected_addresses.contains(&address) => (LatchStatus::Rejected, "address is on the operator protection list".into()),
            Some(address) => match self.mode {
                LatchMode::Monitor => (LatchStatus::Observed, "monitor mode; no firewall change".into()),
                LatchMode::Preview => (LatchStatus::Previewed, preview(address, self.expires_seconds)),
                LatchMode::Manual => (LatchStatus::PendingApproval, preview(address, self.expires_seconds)),
                LatchMode::Automatic => match backend.block(&LatchRequest { address, expires_seconds: self.expires_seconds }) {
                    Ok(detail) => (LatchStatus::Applied, detail),
                    Err(error) => (LatchStatus::Failed, error),
                },
            },
        };
        self.actions.push(LatchAction {
            incident_id: incident.id,
            address,
            mode: self.mode,
            status,
            expires_seconds: self.expires_seconds,
            detail,
            created_at: now(),
        });
        self.actions.last().unwrap()
    }

    pub fn approve<B: LatchBackend>(&mut self, incident_id: u64, backend: &B) -> Result<&LatchAction, String> {
        let action = self.actions.iter_mut().find(|action| action.incident_id == incident_id)
            .ok_or("no TrafficLatch action for this incident")?;
        if action.status != LatchStatus::PendingApproval {
            return Err(format!("action is {}, not pending approval", action.status));
        }
        let address = action.address.ok_or("incident has no blockable address")?;
        match backend.block(&LatchRequest { address, expires_seconds: action.expires_seconds }) {
            Ok(detail) => {
                action.status = LatchStatus::Applied;
                action.detail = detail;
                Ok(action)
            }
            Err(error) => {
                action.status = LatchStatus::Failed;
                action.detail = error.clone();
                Err(error)
            }
        }
    }

    pub fn clear_session(&mut self) {
        self.actions.clear();
    }
}

fn is_blockable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => !address.is_unspecified() && !address.is_loopback() && !address.is_multicast() && !address.is_broadcast(),
        IpAddr::V6(address) => !address.is_unspecified() && !address.is_loopback() && !address.is_multicast(),
    }
}

fn preview(address: IpAddr, seconds: u64) -> String {
    format!("would add {address} to an expiring TrafficLatch set for {seconds} seconds")
}

fn now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::incident::{IncidentSource, IncidentStatus};
    use crate::model::evidence::Severity;

    struct MemoryLatch;
    impl LatchBackend for MemoryLatch {
        fn block(&self, request: &LatchRequest) -> Result<String, String> {
            Ok(format!("memory block {}", request.address))
        }
    }

    fn incident(address: &str) -> Incident {
        Incident {
            id: 1,
            source: IncidentSource::UserRule,
            detector: "test".into(),
            summary: "test".into(),
            severity: Severity::Critical,
            attacker: address.into(),
            target: "10.0.0.5".into(),
            first_packet: 1,
            last_packet: 1,
            first_seen: 1.0,
            last_seen: 1.0,
            status: IncidentStatus::PendingReview,
            reviewed: false,
            packet_history: Vec::new(),
        }
    }

    #[test]
    fn manual_mode_requires_approval_and_uses_expiry() {
        let mut latch = TrafficLatch { mode: LatchMode::Manual, expires_seconds: 60, ..Default::default() };
        assert_eq!(latch.on_incident(&incident("203.0.113.9"), &MemoryLatch).status, LatchStatus::PendingApproval);
        assert_eq!(latch.approve(1, &MemoryLatch).unwrap().status, LatchStatus::Applied);
    }

    #[test]
    fn protected_address_is_never_sent_to_backend() {
        let mut latch = TrafficLatch { mode: LatchMode::Automatic, protected_addresses: vec!["203.0.113.9".parse().unwrap()], ..Default::default() };
        assert_eq!(latch.on_incident(&incident("203.0.113.9"), &MemoryLatch).status, LatchStatus::Rejected);
    }
}
