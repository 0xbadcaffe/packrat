use super::*;
use packrat_tui::analysis::alert_provenance::EvidenceConfidence;

const SIGNATURE: &str = "JNDI label in DNS query";
const CLIENT: &str = "192.0.2.10";
const RESOLVER: &str = "192.0.2.53";

#[test]
fn jndi_dns_lead_requires_a_standalone_wire_question_label() {
    let mut core = AnalysisCore::default();
    let mut wire_query = dns_packet(1, false, CLIENT, RESOLVER, 1, "qa.JnDi.example.test");
    wire_query.info.clear();
    core.analyze(&wire_query);

    let alert = core.alert_center.items.iter().find(|alert| alert.title == SIGNATURE).unwrap();
    assert_eq!(alert.severity, "LOW");
    assert_eq!(alert.packet_refs, [1]);
    assert!(alert.detail.contains("exploitation are unverified"));
    let rule = alert.provenance.as_ref().unwrap();
    assert_eq!(rule.rule_id, "dns.jndi_question_label");
    assert_eq!(rule.confidence, EvidenceConfidence::Heuristic);
    assert!(core.incidents.incidents.is_empty());
}

#[test]
fn jndi_dns_lead_ignores_display_text_substrings_and_non_queries() {
    let mut engine = SecurityEngine::default();
    let mut metadata_only = dns_packet(1, false, CLIENT, RESOLVER, 1, "normal.example.test");
    metadata_only.info = "jndi".into();
    let mut truncated = dns_packet(2, false, CLIENT, RESOLVER, 2, "jndi.example.test");
    truncated.bytes.pop();
    let mut not_dns_port = dns_packet(3, false, CLIENT, RESOLVER, 3, "jndi.example.test");
    not_dns_port.bytes[36..38].copy_from_slice(&5353_u16.to_be_bytes());
    let mut literal_dot = dns_packet(4, false, CLIENT, RESOLVER, 4, "a.jndi.example.test");
    // The wire label is "a.jndi", not two labels, despite display escaping.
    literal_dot.bytes[54..61].copy_from_slice(b"\x06a.jndi");
    let inputs = [
        metadata_only, truncated, not_dns_port, literal_dot,
        dns_packet(5, false, CLIENT, RESOLVER, 5, "notjndi.example.test"),
        dns_packet(6, true, RESOLVER, CLIENT, 6, "jndi.example.test"),
    ];
    for packet in &inputs {
        let findings = engine.inspect(packet);
        assert!(findings.ids.iter().all(|finding| finding.alert.signature != SIGNATURE), "frame {}", packet.no);
    }
}
