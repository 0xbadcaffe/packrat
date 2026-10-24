use super::*;

fn packet(no: u64, target: &str) -> Packet {
    Packet { capture: None,
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
