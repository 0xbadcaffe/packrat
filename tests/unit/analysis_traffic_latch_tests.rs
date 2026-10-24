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
