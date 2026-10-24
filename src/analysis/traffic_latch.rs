//! Expiring, audited containment decisions for critical incidents.

use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::analysis::helper_process::spawn_stdin_stdout_helper;
use crate::analysis::incident::Incident;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LatchStatus {
    Observed,
    Previewed,
    PendingApproval,
    Applied,
    Expired,
    Revoked,
    RevokeFailed,
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
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::RevokeFailed => "revoke failed",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LatchAction {
    pub incident_id: u64,
    pub address: Option<IpAddr>,
    pub mode: LatchMode,
    pub status: LatchStatus,
    pub expires_seconds: u64,
    pub detail: String,
    pub created_at: f64,
}

impl LatchAction {
    fn expires_at(&self) -> f64 {
        self.created_at + self.expires_seconds as f64
    }

    fn is_active_at(&self, timestamp: f64) -> bool {
        matches!(self.status, LatchStatus::Applied | LatchStatus::RevokeFailed)
            && timestamp < self.expires_at()
    }
}

#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LatchOperation {
    #[default]
    Block,
    Unblock,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LatchRequest {
    pub address: IpAddr,
    pub expires_seconds: u64,
    #[serde(default, skip_serializing_if = "is_block_operation")]
    pub operation: LatchOperation,
}

fn is_block_operation(operation: &LatchOperation) -> bool {
    *operation == LatchOperation::Block
}

pub trait LatchBackend {
    fn block(&self, request: &LatchRequest) -> Result<String, String>;

    fn unblock(&self, _request: &LatchRequest) -> Result<String, String> {
        Err("containment backend does not support immediate revocation".into())
    }
}

#[derive(Debug)]
pub struct CommandLatch {
    pub program: PathBuf,
}

#[derive(Debug, serde::Deserialize)]
struct HelperResponse {
    ok: bool,
    detail: String,
}

impl CommandLatch {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self { program: path.as_ref().to_path_buf() }
    }
}

impl LatchBackend for CommandLatch {
    fn block(&self, request: &LatchRequest) -> Result<String, String> {
        self.execute(request)
    }

    fn unblock(&self, request: &LatchRequest) -> Result<String, String> {
        self.execute(request)
    }
}

impl CommandLatch {
    fn execute(&self, request: &LatchRequest) -> Result<String, String> {
        let mut child = spawn_stdin_stdout_helper(&self.program, "latch")?;
        let input = serde_json::to_vec(request)
            .map_err(|error| format!("encode latch helper request: {error}"))?;
        child.stdin.as_mut().ok_or("latch helper stdin unavailable")?
            .write_all(&input).map_err(|error| format!("write latch helper request: {error}"))?;
        let output = child.wait_with_output().map_err(|error| format!("wait for latch helper: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "latch helper failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let response: HelperResponse = serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("decode latch helper response: {error}"))?;
        if response.ok { Ok(response.detail) } else { Err(response.detail) }
    }
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


    fn unblock(&self, request: &LatchRequest) -> Result<String, String> {
        #[cfg(target_os = "linux")]
        {
            let set = match request.address {
                IpAddr::V4(_) => "blocked_v4",
                IpAddr::V6(_) => "blocked_v6",
            };
            let output = Command::new("nft")
                .args(["delete", "element", "inet", "packrat_latch", set, "{", &request.address.to_string(), "}"])
                .output()
                .map_err(|error| format!("run nft: {error}"))?;
            if !output.status.success() {
                return Err(format!("nft unblock failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
            }
            Ok(format!("removed {} from the TrafficLatch set", request.address))
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

#[derive(Debug, Clone)]
pub struct TrafficLatch {
    pub mode: LatchMode,
    pub expires_seconds: u64,
    pub protected_addresses: Vec<IpAddr>,
    pub actions: Vec<LatchAction>,
    pub max_active_blocks: usize,
    pub emergency_stop: bool,
}

impl Default for TrafficLatch {
    fn default() -> Self {
        Self {
            mode: LatchMode::Monitor,
            expires_seconds: 900,
            protected_addresses: Vec::new(),
            actions: Vec::new(),
            max_active_blocks: 32,
            emergency_stop: false,
        }
    }
}

impl TrafficLatch {
    /// Historical and synthetic evidence can be inspected, never enforced.
    pub fn observe_offline_incident(&mut self, incident: &Incident) {
        if self.actions.iter().any(|action| action.incident_id == incident.id) { return; }
        self.actions.push(LatchAction {
            incident_id: incident.id,
            address: incident.attacker.parse().ok(),
            mode: self.mode,
            status: LatchStatus::Observed,
            expires_seconds: self.expires_seconds,
            detail: "Offline, synthetic, or mixed evidence; containment disabled until a clean live session".into(),
            created_at: now(),
        });
    }

    pub fn on_incident(&mut self, incident: &Incident, backend: &dyn LatchBackend) -> &LatchAction {
        self.on_incident_with_auto_gate(incident, backend, false)
    }

    pub fn on_incident_with_auto_gate(
        &mut self,
        incident: &Incident,
        backend: &dyn LatchBackend,
        automatic_allowed: bool,
    ) -> &LatchAction {
        self.reconcile_expired();
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
                LatchMode::Automatic if self.emergency_stop => (
                    LatchStatus::Rejected,
                    "Guard kill switch is engaged; no firewall change".into(),
                ),
                LatchMode::Automatic if !automatic_allowed => (
                    LatchStatus::PendingApproval,
                    format!("automatic gate not satisfied; {}", preview(address, self.expires_seconds)),
                ),
                LatchMode::Automatic if self.active_count() >= self.max_active_blocks => (
                    LatchStatus::Rejected,
                    format!("Guard maximum of {} active blocks reached", self.max_active_blocks),
                ),
                LatchMode::Automatic => {
                    match backend.block(&LatchRequest::block(address, self.expires_seconds)) {
                        Ok(detail) => (LatchStatus::Applied, detail),
                        Err(error) => (LatchStatus::Failed, error),
                    }
                }
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

    pub fn approve(&mut self, incident_id: u64, backend: &dyn LatchBackend) -> Result<&LatchAction, String> {
        self.reconcile_expired();
        if self.emergency_stop {
            return Err("Guard kill switch is engaged".into());
        }
        if self.active_count() >= self.max_active_blocks {
            return Err(format!("Guard maximum of {} active blocks reached", self.max_active_blocks));
        }
        let action = self.actions.iter_mut().find(|action| action.incident_id == incident_id)
            .ok_or("no TrafficLatch action for this incident")?;
        if action.status != LatchStatus::PendingApproval {
            return Err(format!("action is {}, not pending approval", action.status));
        }
        let address = action.address.ok_or("incident has no blockable address")?;
        match backend.block(&LatchRequest::block(address, action.expires_seconds)) {
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

    pub fn active_count(&self) -> usize {
        self.active_count_at(now())
    }

    fn active_count_at(&self, timestamp: f64) -> usize {
        self.actions.iter().filter(|action| action.is_active_at(timestamp)).count()
    }

    pub fn reconcile_expired(&mut self) {
        self.reconcile_expired_at(now());
    }

    fn reconcile_expired_at(&mut self, timestamp: f64) {
        for action in &mut self.actions {
            if action.is_active_at(timestamp) || !matches!(action.status, LatchStatus::Applied | LatchStatus::RevokeFailed) {
                continue;
            }
            action.status = LatchStatus::Expired;
            action.detail = format!("containment expired after {} seconds", action.expires_seconds);
        }
    }

    pub fn engage_kill_switch(&mut self, backend: &dyn LatchBackend) -> (usize, usize) {
        self.emergency_stop = true;
        self.mode = LatchMode::Monitor;
        self.reconcile_expired();
        let mut revoked = 0;
        let mut failed = 0;
        for action in &mut self.actions {
            if !matches!(action.status, LatchStatus::Applied | LatchStatus::RevokeFailed) {
                continue;
            }
            let Some(address) = action.address else { continue };
            let request = LatchRequest::unblock(address, action.expires_seconds);
            match backend.unblock(&request) {
                Ok(detail) => {
                    action.status = LatchStatus::Revoked;
                    action.detail = detail;
                    revoked += 1;
                }
                Err(error) => {
                    action.status = LatchStatus::RevokeFailed;
                    action.detail = error;
                    failed += 1;
                }
            }
        }
        (revoked, failed)
    }

    pub fn clear_kill_switch(&mut self) {
        self.emergency_stop = false;
    }

    /// Evaluate Guard policy without calling any containment backend.
    pub fn simulate_incident(&self, incident: &Incident, automatic_allowed: bool) -> LatchAction {
        let address = incident.attacker.parse::<IpAddr>().ok();
        let (status, detail) = match address {
            None => (LatchStatus::Rejected, "attacker is not a valid IP address".into()),
            Some(address) if !is_blockable(address) => (LatchStatus::Rejected, "special-purpose address is protected".into()),
            Some(address) if self.protected_addresses.contains(&address) => (LatchStatus::Rejected, "address is on the operator protection list".into()),
            Some(_) if self.emergency_stop => (LatchStatus::Rejected, "Guard kill switch is engaged".into()),
            Some(_) if self.active_count() >= self.max_active_blocks => (
                LatchStatus::Rejected,
                format!("Guard maximum of {} active blocks reached", self.max_active_blocks),
            ),
            Some(address) if !automatic_allowed => (
                LatchStatus::PendingApproval,
                format!("automatic gate not satisfied; {}", preview(address, self.expires_seconds)),
            ),
            Some(address) => (LatchStatus::Previewed, preview(address, self.expires_seconds)),
        };
        LatchAction {
            incident_id: incident.id,
            address,
            mode: LatchMode::Preview,
            status,
            expires_seconds: self.expires_seconds,
            detail,
            created_at: now(),
        }
    }
}

impl LatchRequest {
    fn block(address: IpAddr, expires_seconds: u64) -> Self {
        Self { address, expires_seconds, operation: LatchOperation::Block }
    }

    fn unblock(address: IpAddr, expires_seconds: u64) -> Self {
        Self { address, expires_seconds, operation: LatchOperation::Unblock }
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
#[path = "../../tests/unit/analysis_traffic_latch_tests.rs"]
mod tests;
