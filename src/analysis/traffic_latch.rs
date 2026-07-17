//! Expiring, audited containment decisions for critical incidents.

use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::analysis::helper_process::spawn_stdin_stdout_helper;
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
mod tests {
    use super::*;
    use crate::analysis::incident::{IncidentSource, IncidentStatus};
    use crate::model::evidence::Severity;

    struct MemoryLatch;
    impl LatchBackend for MemoryLatch {
        fn block(&self, request: &LatchRequest) -> Result<String, String> {
            Ok(format!("memory block {}", request.address))
        }

        fn unblock(&self, request: &LatchRequest) -> Result<String, String> {
            assert_eq!(request.operation, LatchOperation::Unblock);
            Ok(format!("memory unblock {}", request.address))
        }
    }

    struct ForbiddenLatch;
    impl LatchBackend for ForbiddenLatch {
        fn block(&self, _request: &LatchRequest) -> Result<String, String> {
            panic!("containment backend must not be called")
        }
    }

    struct FailingLatch;
    impl LatchBackend for FailingLatch {
        fn block(&self, _request: &LatchRequest) -> Result<String, String> {
            Err("firewall unavailable".into())
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
        assert_eq!(latch.on_incident_with_auto_gate(&incident("203.0.113.9"), &MemoryLatch, true).status, LatchStatus::Rejected);
    }

    #[test]
    fn automatic_mode_requires_policy_gate() {
        let mut latch = TrafficLatch { mode: LatchMode::Automatic, expires_seconds: 60, ..Default::default() };
        assert_eq!(
            latch.on_incident_with_auto_gate(&incident("203.0.113.9"), &MemoryLatch, false).status,
            LatchStatus::PendingApproval,
        );
        assert!(latch.actions[0].detail.contains("automatic gate not satisfied"));

        let mut allowed = TrafficLatch { mode: LatchMode::Automatic, expires_seconds: 60, ..Default::default() };
        assert_eq!(
            allowed.on_incident_with_auto_gate(&incident("203.0.113.9"), &MemoryLatch, true).status,
            LatchStatus::Applied,
        );
    }

    #[test]
    fn monitor_and_preview_modes_never_call_backend() {
        let mut monitor = TrafficLatch::default();
        assert_eq!(monitor.on_incident(&incident("203.0.113.9"), &ForbiddenLatch).status, LatchStatus::Observed);

        let mut preview = TrafficLatch { mode: LatchMode::Preview, expires_seconds: 120, ..Default::default() };
        let action = preview.on_incident(&incident("203.0.113.9"), &ForbiddenLatch);
        assert_eq!(action.status, LatchStatus::Previewed);
        assert!(action.detail.contains("120 seconds"));
    }

    #[test]
    fn invalid_and_special_purpose_attackers_are_rejected() {
        for address in ["not-an-address", "127.0.0.1", "0.0.0.0", "::1", "ff02::1"] {
            let mut latch = TrafficLatch { mode: LatchMode::Automatic, ..Default::default() };
            assert_eq!(
                latch.on_incident_with_auto_gate(&incident(address), &ForbiddenLatch, true).status,
                LatchStatus::Rejected,
                "{address} must not reach the firewall backend",
            );
        }
    }

    #[test]
    fn backend_failure_is_audited_and_duplicate_incident_is_not_retried() {
        let mut latch = TrafficLatch { mode: LatchMode::Automatic, ..Default::default() };
        let first = latch.on_incident_with_auto_gate(&incident("203.0.113.9"), &FailingLatch, true);
        assert_eq!(first.status, LatchStatus::Failed);
        assert_eq!(first.detail, "firewall unavailable");
        let duplicate = latch.on_incident_with_auto_gate(&incident("203.0.113.9"), &MemoryLatch, true);
        assert_eq!(duplicate.status, LatchStatus::Failed);
        assert_eq!(latch.actions.len(), 1);
    }

    #[test]
    fn response_simulation_never_calls_backend_and_reports_policy_gate() {
        let latch = TrafficLatch { expires_seconds: 120, ..Default::default() };
        let pending = latch.simulate_incident(&incident("203.0.113.9"), false);
        assert_eq!(pending.status, LatchStatus::PendingApproval);
        let allowed = latch.simulate_incident(&incident("203.0.113.9"), true);
        assert_eq!(allowed.status, LatchStatus::Previewed);
        assert!(allowed.detail.contains("120 seconds"));
    }

    #[test]
    fn guard_kill_switch_forces_monitor_and_rejects_future_actions() {
        let mut latch = TrafficLatch { mode: LatchMode::Automatic, ..Default::default() };
        latch.engage_kill_switch(&MemoryLatch);
        assert_eq!(latch.mode, LatchMode::Monitor);
        assert!(latch.emergency_stop);
        assert_eq!(latch.simulate_incident(&incident("203.0.113.9"), true).status, LatchStatus::Rejected);
    }

    #[test]
    fn kill_switch_prevents_manual_approval() {
        let mut latch = TrafficLatch { mode: LatchMode::Manual, ..Default::default() };
        latch.on_incident(&incident("203.0.113.9"), &MemoryLatch);
        latch.engage_kill_switch(&MemoryLatch);
        assert_eq!(latch.approve(1, &ForbiddenLatch).unwrap_err(), "Guard kill switch is engaged");
    }

    #[test]
    fn expired_blocks_do_not_consume_the_active_limit() {
        let mut latch = TrafficLatch { mode: LatchMode::Automatic, max_active_blocks: 1, expires_seconds: 10, ..Default::default() };
        latch.on_incident_with_auto_gate(&incident("203.0.113.9"), &MemoryLatch, true);
        let expired_at = latch.actions[0].created_at + 11.0;
        assert_eq!(latch.active_count_at(expired_at), 0);
        latch.reconcile_expired_at(expired_at);
        assert_eq!(latch.actions[0].status, LatchStatus::Expired);
    }

    #[test]
    fn kill_switch_revokes_active_blocks_and_audits_them() {
        let mut latch = TrafficLatch { mode: LatchMode::Automatic, ..Default::default() };
        latch.on_incident_with_auto_gate(&incident("203.0.113.9"), &MemoryLatch, true);
        let (revoked, failed) = latch.engage_kill_switch(&MemoryLatch);
        assert_eq!((revoked, failed), (1, 0));
        assert_eq!(latch.actions[0].status, LatchStatus::Revoked);
        assert_eq!(latch.active_count(), 0);
    }

    #[test]
    fn failed_revocation_remains_active_until_expiry() {
        let mut latch = TrafficLatch { mode: LatchMode::Automatic, expires_seconds: 60, ..Default::default() };
        latch.on_incident_with_auto_gate(&incident("203.0.113.9"), &MemoryLatch, true);
        let (revoked, failed) = latch.engage_kill_switch(&FailingLatch);
        assert_eq!((revoked, failed), (0, 1));
        assert_eq!(latch.actions[0].status, LatchStatus::RevokeFailed);
        assert_eq!(latch.active_count(), 1);
    }

    #[test]
    fn guard_rejects_actions_at_configured_block_limit() {
        let mut latch = TrafficLatch {
            mode: LatchMode::Automatic,
            max_active_blocks: 0,
            ..Default::default()
        };
        let action = latch.on_incident_with_auto_gate(&incident("203.0.113.9"), &ForbiddenLatch, true);
        assert_eq!(action.status, LatchStatus::Rejected);
        assert!(action.detail.contains("maximum"));
    }

    #[cfg(unix)]
    #[test]
    fn command_latch_uses_json_helper_contract() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!("packrat-latch-helper-{}-{}.sh", std::process::id(), unique_test_suffix()));
        std::fs::write(
            &path,
            "#!/bin/sh\ncat >/dev/null\nprintf '{\"ok\":true,\"detail\":\"helper block accepted\"}'\n",
        ).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).unwrap();

        let backend = CommandLatch::new(&path);
        let detail = backend.block(&LatchRequest {
            address: "203.0.113.9".parse().unwrap(),
            expires_seconds: 60,
            operation: LatchOperation::Block,
        }).unwrap();
        assert_eq!(detail, "helper block accepted");
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    fn unique_test_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    }
}
