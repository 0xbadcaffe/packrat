use super::*;

#[test]
fn lookup_marker_is_a_heuristic_lead_and_requires_transport_payload() {
    use packrat_tui::analysis::alert_provenance::EvidenceConfidence;
    use packrat_tui::engine::AnalysisCore;

    let mut core = AnalysisCore::default();
    let mut trailer = ipv4_tcp_packet(1, 100, 0x18, b"benign");
    trailer.bytes.extend_from_slice(b"${jndi:");
    let mut options = ipv4_tcp_packet(2, 101, 0x18, b"${jndi:x");
    options.bytes[46] = 0x70; // The eight bytes are part of the TCP header.
    core.analyze(&trailer);
    core.analyze(&options);
    assert!(core.alert_center.items.iter().all(|alert| !alert.title.contains("Log4Shell")));

    core.analyze(&ipv4_tcp_packet(3, 200, 0x18, b"${jndi:"));
    let alert = core.alert_center.items.iter().find(|alert| alert.title.contains("Log4Shell")).unwrap();
    assert_eq!(alert.severity, "MEDIUM");
    assert_eq!(alert.packet_refs, [3]);
    assert!(alert.detail.contains("lookup execution are unverified"));
    let provenance = alert.provenance.as_ref().unwrap();
    assert_eq!(provenance.rule_id, "log4j.literal_lookup_marker");
    assert_eq!(provenance.confidence, EvidenceConfidence::Heuristic);
    assert!(core.incidents.incidents.is_empty());

    let mut udp = ipv4_tcp_packet(4, 0, 0, b"${jndi:");
    udp.bytes.drain(42..54);
    udp.bytes[16..18].copy_from_slice(&35_u16.to_be_bytes());
    udp.bytes[23] = 17;
    udp.bytes[38..40].copy_from_slice(&15_u16.to_be_bytes());
    let mut engine = SecurityEngine::default();
    assert!(engine.inspect(&udp).ids.iter().any(|finding| finding.alert.signature.contains("Log4Shell")));
    udp.bytes[38..40].copy_from_slice(&8_u16.to_be_bytes());
    assert!(engine.inspect(&udp).ids.iter().all(|finding| !finding.alert.signature.contains("Log4Shell")));
}
