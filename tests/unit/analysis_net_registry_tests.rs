use super::*;

#[test]
fn longest_prefix_map_enriches_observed_address() {
    let path = std::env::temp_dir().join(format!("packrat-prefix-{}.csv", std::process::id()));
    std::fs::write(&path, "203.0.113.0/24,AS64500,Example Network\n").unwrap();
    let mut registry = NetRegistry::default();
    assert_eq!(registry.load_map(&path).unwrap(), 1);
    registry.observe("203.0.113.9");
    let identity = registry.observed.get(&"203.0.113.9".parse().unwrap()).unwrap();
    assert_eq!(identity.asn.as_deref(), Some("AS64500"));
    assert_eq!(identity.organization, "Example Network");
    let _ = std::fs::remove_file(path);
}

#[test]
fn reputation_map_marks_addresses_and_fingerprints() {
    let path = std::env::temp_dir().join(format!("packrat-reputation-{}.csv", std::process::id()));
    std::fs::write(
        &path,
        "203.0.113.0/24,high,test block,lab\nratq1_deadbeefcafe,medium,known quic shape,lab\n",
    ).unwrap();
    let mut registry = NetRegistry::default();
    assert_eq!(registry.load_reputation(&path).unwrap(), 2);
    registry.observe("203.0.113.9");
    let identity = registry.observed.get(&"203.0.113.9".parse().unwrap()).unwrap();
    assert_eq!(identity.reputation.as_ref().unwrap().label, "test block");
    assert_eq!(
        registry.reputation_for_fingerprint("RATQ1_DEADBEEFCAFE").unwrap().severity,
        "medium",
    );
    let _ = std::fs::remove_file(path);
}

#[cfg(unix)]
#[test]
fn helper_refresh_marks_selected_address_reputation() {
    use std::os::unix::fs::PermissionsExt;

    let path = std::env::temp_dir().join(format!("packrat-reputation-helper-{}-{}.sh", std::process::id(), unique_test_suffix()));
    std::fs::write(
        &path,
        "#!/bin/sh\ncat >/dev/null\nprintf '{\"ok\":true,\"severity\":\"high\",\"label\":\"helper listed\",\"source\":\"unit helper\"}'\n",
    ).unwrap();
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions).unwrap();

    let mut registry = NetRegistry::default();
    let identity = registry
        .refresh_reputation_with_helper("203.0.113.9".parse().unwrap(), &path)
        .unwrap();
    let finding = identity.reputation.as_ref().unwrap();
    assert_eq!(finding.severity, "high");
    assert_eq!(finding.label, "helper listed");
    assert_eq!(finding.source, "unit helper");
    let _ = std::fs::remove_file(path);
}

#[cfg(unix)]
#[test]
fn helper_refresh_caches_fingerprint_reputation() {
    use std::os::unix::fs::PermissionsExt;

    let path = std::env::temp_dir().join(format!("packrat-fingerprint-helper-{}-{}.sh", std::process::id(), unique_test_suffix()));
    std::fs::write(
        &path,
        "#!/bin/sh\ncat >/dev/null\nprintf '{\"ok\":true,\"severity\":\"medium\",\"label\":\"fingerprint listed\",\"source\":\"unit helper\"}'\n",
    ).unwrap();
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions).unwrap();

    let mut registry = NetRegistry::default();
    let finding = registry
        .refresh_fingerprint_reputation_with_helper("ratq1_deadbeefcafe", &path)
        .unwrap();
    assert_eq!(finding.label, "fingerprint listed");
    assert_eq!(
        registry.reputation_for_fingerprint("ratq1_deadbeefcafe").unwrap().severity,
        "medium",
    );
    let _ = std::fs::remove_file(path);
}

#[cfg(unix)]
fn unique_test_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}
