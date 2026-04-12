//! Tests for the "Operation Quiet Beacon" correlated simulation scenario.

use packrat_tui::sim::scenario;

// ── build() ───────────────────────────────────────────────────────────────────

#[test]
fn build_produces_packets() {
    let pkts = scenario::build();
    assert!(!pkts.is_empty(), "scenario should produce packets");
}

#[test]
fn build_produces_expected_volume() {
    let pkts = scenario::build();
    // Scenario has: 2 ARP + 7 DNS + 3 HTTP + 2 FTP + 60 beacon + 4 TLS +
    //               10 Kerberos + 4 SMB + 2 ICMP + 2 Modbus + 1 MQTT + 1 NTP + 1 HTTP = ~99 pkts
    assert!(pkts.len() >= 90, "expected at least 90 packets, got {}", pkts.len());
}

#[test]
fn build_packet_numbers_are_sequential() {
    let pkts = scenario::build();
    for (i, p) in pkts.iter().enumerate() {
        assert_eq!(p.no, (i + 1) as u64,
            "packet at index {i} should have no={}, got {}", i + 1, p.no);
    }
}

#[test]
fn build_timestamps_are_non_decreasing() {
    let pkts = scenario::build();
    for w in pkts.windows(2) {
        assert!(w[1].timestamp >= w[0].timestamp,
            "timestamps must be non-decreasing: {} < {}", w[1].timestamp, w[0].timestamp);
    }
}

#[test]
fn build_has_arp_packets() {
    let pkts = scenario::build();
    let arp: Vec<_> = pkts.iter().filter(|p| p.protocol == "ARP").collect();
    assert!(!arp.is_empty(), "scenario should include ARP packets");
}

#[test]
fn build_has_dns_packets() {
    let pkts = scenario::build();
    let dns: Vec<_> = pkts.iter().filter(|p| p.protocol == "DNS").collect();
    // Expect at least 6 DNS packets (1 normal + 5 tunnel queries)
    assert!(dns.len() >= 6, "expected >=6 DNS packets, got {}", dns.len());
}

#[test]
fn build_dns_has_high_entropy_subdomain() {
    let pkts = scenario::build();
    let tunnel_dns: Vec<_> = pkts.iter()
        .filter(|p| p.protocol == "DNS" && p.info.contains("evil-tunnel.com"))
        .collect();
    assert!(!tunnel_dns.is_empty(), "scenario should have DNS tunnel queries");
}

#[test]
fn build_has_http_with_basic_auth() {
    let pkts = scenario::build();
    let http_auth: Vec<_> = pkts.iter()
        .filter(|p| p.protocol == "HTTP" && p.info.contains("Authorization"))
        .collect();
    assert!(!http_auth.is_empty(), "scenario should have HTTP Basic auth packet");
}

#[test]
fn build_has_ftp_cleartext_credentials() {
    let pkts = scenario::build();
    let ftp_pass: Vec<_> = pkts.iter()
        .filter(|p| p.protocol == "FTP" && p.info.contains("PASS"))
        .collect();
    assert!(!ftp_pass.is_empty(), "scenario should have FTP PASS packet");
}

#[test]
fn build_has_beacon_traffic_to_c2() {
    let pkts = scenario::build();
    let c2_pkts: Vec<_> = pkts.iter()
        .filter(|p| p.dst == "203.0.113.7" && p.protocol == "TCP")
        .collect();
    // 30 beacon packets to C2
    assert_eq!(c2_pkts.len(), 30, "expected 30 beacon packets to C2");
}

#[test]
fn build_has_tls_with_rc4() {
    let pkts = scenario::build();
    let tls_rc4: Vec<_> = pkts.iter()
        .filter(|p| p.protocol == "TLS" && p.info.contains("RC4"))
        .collect();
    assert!(!tls_rc4.is_empty(), "scenario should have TLS with RC4 cipher");
}

#[test]
fn build_has_kerberos_spray() {
    let pkts = scenario::build();
    let kerb: Vec<_> = pkts.iter()
        .filter(|p| p.protocol == "Kerberos" && p.info.contains("AS-REQ"))
        .collect();
    // 5 accounts sprayed
    assert_eq!(kerb.len(), 5, "expected 5 Kerberos AS-REQ packets");
}

#[test]
fn build_has_smb_lateral_movement() {
    let pkts = scenario::build();
    let smb: Vec<_> = pkts.iter()
        .filter(|p| p.protocol == "SMB")
        .collect();
    assert!(smb.len() >= 4, "expected at least 4 SMB packets");
}

#[test]
fn build_has_iot_protocols() {
    let pkts = scenario::build();
    let modbus = pkts.iter().any(|p| p.protocol == "Modbus");
    let mqtt   = pkts.iter().any(|p| p.protocol == "MQTT");
    assert!(modbus, "scenario should include Modbus packets");
    assert!(mqtt, "scenario should include MQTT packets");
}

#[test]
fn build_victim_src_is_192_168_1_50() {
    let pkts = scenario::build();
    let victim_pkts: Vec<_> = pkts.iter().filter(|p| p.src == "192.168.1.50").collect();
    assert!(!victim_pkts.is_empty(), "victim IP should appear as source");
}

#[test]
fn build_packets_have_nonzero_length() {
    let pkts = scenario::build();
    for p in &pkts {
        assert!(p.length > 0, "packet {} should have nonzero length", p.no);
    }
}

#[test]
fn build_packets_have_bytes_matching_length() {
    let pkts = scenario::build();
    for p in &pkts {
        assert_eq!(p.bytes.len(), p.length as usize,
            "packet {} bytes.len()={} but length={}", p.no, p.bytes.len(), p.length);
    }
}

// ── ioc_ips() ─────────────────────────────────────────────────────────────────

#[test]
fn ioc_ips_contains_c2() {
    let ips = scenario::ioc_ips();
    assert!(ips.contains(&"203.0.113.7"), "IOC list must include C2 IP");
}

#[test]
fn ioc_ips_returns_multiple() {
    let ips = scenario::ioc_ips();
    assert!(ips.len() >= 2, "should have at least 2 IOC IPs");
}

// ── notebook_notes() ──────────────────────────────────────────────────────────

#[test]
fn notebook_notes_non_empty() {
    let notes = scenario::notebook_notes();
    assert!(!notes.is_empty(), "scenario should have pre-written notes");
}

#[test]
fn notebook_notes_all_have_text() {
    for (text, _ev) in scenario::notebook_notes() {
        assert!(!text.is_empty(), "each note must have non-empty text");
    }
}

#[test]
fn notebook_notes_some_have_evidence() {
    let notes = scenario::notebook_notes();
    let with_ev = notes.iter().filter(|(_, ev)| ev.is_some()).count();
    assert!(with_ev > 0, "at least some notes should have evidence references");
}

// ── host_tags() ───────────────────────────────────────────────────────────────

#[test]
fn host_tags_non_empty() {
    let tags = scenario::host_tags();
    assert!(!tags.is_empty(), "scenario should define host tags");
}

#[test]
fn host_tags_victim_marked_compromised() {
    let tags = scenario::host_tags();
    let victim = tags.iter().find(|(ip, _)| *ip == "192.168.1.50");
    assert!(victim.is_some(), "victim IP should be in host_tags");
    let (_, vtags) = victim.unwrap();
    assert!(vtags.contains(&"compromised"), "victim should be tagged compromised");
}

#[test]
fn host_tags_c2_marked_ioc() {
    let tags = scenario::host_tags();
    let c2 = tags.iter().find(|(ip, _)| *ip == "203.0.113.7");
    assert!(c2.is_some(), "C2 IP should be in host_tags");
    let (_, ctags) = c2.unwrap();
    assert!(ctags.contains(&"ioc"), "C2 should be tagged ioc");
}
