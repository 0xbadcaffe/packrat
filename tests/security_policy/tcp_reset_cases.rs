use super::{SecurityEngine, ipv4_tcp_packet};
use packrat_tui::engine::AnalysisCore;

const TITLE: &str = "TCP payload after reset";

#[test]
fn detects_tcp_payload_continuing_after_reset() {
    let mut core = AnalysisCore::default();
    core.analyze(&ipv4_tcp_packet(1, 90, 0x18, b"previous"));
    core.analyze(&ipv4_tcp_packet(2, 100, 0x04, b""));
    core.analyze(&ipv4_tcp_packet(3, 90, 0x18, b"previous"));
    assert!(!core.alert_center.items.iter().any(|alert| alert.title == TITLE));

    core.analyze(&ipv4_tcp_packet(4, 101, 0x18, b"later"));
    let alert = core.alert_center.items.iter().find(|alert| alert.title == TITLE).unwrap();
    assert_eq!(alert.packet_refs, [2, 4]);
    assert_eq!(alert.packet_no, 4);
    assert_eq!(alert.severity, "MEDIUM");
    let rule = alert.provenance.as_ref().unwrap();
    assert_eq!(rule.rule_id, "tcp.payload_after_observed_reset");
    assert_eq!(rule.confidence.to_string(), "Heuristic");
    assert!(alert.detail.contains("payload seq 101 followed reset frame #2 (same direction, seq 100)"));
    assert!(alert.detail.contains("reset acceptance and on-wire ordering unverified"));
}

#[test]
fn tcp_reset_correlation_ignores_other_vlans_earlier_payload_and_new_connections() {
    let mut security = SecurityEngine::default();
    let mut reset = ipv4_tcp_packet(10, 100, 0x04, b"");
    reset.vlan_id = Some(10);
    security.update(&reset);

    let mut earlier = ipv4_tcp_packet(11, 101, 0x18, b"earlier timestamp");
    earlier.timestamp = 9.0;
    earlier.vlan_id = Some(10);
    let mut other_vlan = ipv4_tcp_packet(12, 120, 0x18, b"other VLAN");
    other_vlan.vlan_id = Some(20);
    let mut new_syn = ipv4_tcp_packet(13, 300, 0x02, b"");
    new_syn.vlan_id = Some(10);
    let mut new_data = ipv4_tcp_packet(14, 301, 0x18, b"new connection");
    new_data.vlan_id = Some(10);
    for packet in [earlier, other_vlan, new_syn, new_data] {
        let findings = security.inspect(&packet);
        assert!(findings.ids.iter().all(|finding| finding.alert.signature != TITLE));
    }
}

#[test]
fn tcp_reset_correlation_does_not_use_an_incomplete_ip_datagram() {
    let mut security = SecurityEngine::default();
    let mut partial_reset = ipv4_tcp_packet(1, 100, 0x04, b"");
    partial_reset.bytes[20] = 0x20; // IPv4 more-fragments flag.
    security.update(&partial_reset);
    let findings = security.inspect(&ipv4_tcp_packet(2, 101, 0x18, b"normal traffic"));
    assert!(findings.ids.iter().all(|finding| finding.alert.signature != TITLE));
}

#[test]
fn conflicting_tcp_retransmission_links_both_frames_across_sequence_wrap() {
    let mut core = AnalysisCore::default();
    core.analyze(&ipv4_tcp_packet(1, u32::MAX - 2, 0x18, b"ABCD"));
    core.analyze(&ipv4_tcp_packet(2, 0, 0x18, b"D"));
    assert!(core.alert_center.items.iter().all(|alert| alert.title != "Conflicting TCP retransmission"));
    core.analyze(&ipv4_tcp_packet(3, 0, 0x18, b"X"));
    let alert = core.alert_center.items.iter().find(|alert| alert.title == "Conflicting TCP retransmission").unwrap();
    assert_eq!(alert.packet_refs, [1, 3]);
    assert!(alert.detail.contains("TCP sequence 0 (1 overlapping bytes compared)"));
    assert!(alert.detail.contains("receiver outcome unverified"));
    assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "tcp.conflicting_retransmission");
    assert!(core.incidents.incidents.is_empty());
}

#[test]
fn conflicting_tcp_retransmission_accounts_for_syn_before_payload() {
    let mut engine = SecurityEngine::default();
    engine.update(&ipv4_tcp_packet(1, 100, 0x02, b"abc"));
    assert!(engine.inspect(&ipv4_tcp_packet(2, 101, 0x18, b"abc")).ids.is_empty());
    let mut other_vlan = ipv4_tcp_packet(3, 102, 0x18, b"X");
    other_vlan.vlan_id = Some(100);
    assert!(engine.inspect(&other_vlan).ids.is_empty());
    let findings = engine.inspect(&ipv4_tcp_packet(4, 102, 0x18, b"X"));
    let alert = findings.ids.iter().find(|finding| finding.alert.signature == "Conflicting TCP retransmission").unwrap();
    assert_eq!(alert.related_packets, [1]);
    assert!(alert.alert.detail.contains("TCP sequence 102"));
}
