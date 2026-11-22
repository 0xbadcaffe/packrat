use packrat_tui::analysis::industrial_policy;
use packrat_tui::net::packet::Packet;
use packrat_tui::net::security::{SecurityEngine, Severity};

fn industrial_packet(protocol: &str, port: u16, tcp: bool, payload: &[u8]) -> Packet {
    let transport_header_len = if tcp { 20 } else { 8 };
    let mut bytes = vec![0_u8; 14 + 20 + transport_header_len];
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&((20 + transport_header_len + payload.len()) as u16).to_be_bytes());
    bytes[23] = if tcp { 6 } else { 17 };
    bytes[26..30].copy_from_slice(&[10, 0, 0, 5]);
    bytes[30..34].copy_from_slice(&[10, 0, 0, 10]);
    bytes[34..36].copy_from_slice(&50_000_u16.to_be_bytes());
    bytes[36..38].copy_from_slice(&port.to_be_bytes());
    if tcp {
        bytes[46] = 0x50;
        bytes[47] = 0x18;
    } else {
        bytes[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    }
    bytes.extend_from_slice(payload);
    Packet { capture: None,
        no: 1,
        timestamp: 1.0,
        src: "10.0.0.5".into(),
        dst: "10.0.0.10".into(),
        protocol: protocol.into(),
        length: bytes.len() as u16,
        info: String::new(),
        src_port: Some(50_000),
        dst_port: Some(port),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes,
    }
}

#[test]
fn identifies_state_changing_modbus_dnp3_s7_and_bacnet_operations() {
    let mut modbus = vec![0_u8; 8];
    modbus[5] = 2;
    modbus[7] = 16;

    let mut dnp3 = vec![0_u8; 13];
    dnp3[..2].copy_from_slice(&[0x05, 0x64]);
    dnp3[12] = 0x04;

    let mut s7 = vec![0_u8; 18];
    s7[..2].copy_from_slice(&[0x03, 0x00]);
    s7[7] = 0x32;
    s7[17] = 0x05;

    let mut bacnet = vec![0_u8; 10];
    bacnet[0] = 0x81;
    bacnet[4] = 0x01;
    bacnet[9] = 20;

    let findings = [
        industrial_policy::inspect(&industrial_packet("Modbus", 502, true, &modbus)).unwrap(),
        industrial_policy::inspect(&industrial_packet("DNP3", 20_000, true, &dnp3)).unwrap(),
        industrial_policy::inspect(&industrial_packet("S7comm", 102, true, &s7)).unwrap(),
        industrial_policy::inspect(&industrial_packet("BACnet", 47_808, false, &bacnet)).unwrap(),
    ];
    assert_eq!(findings[0].operation, "write multiple registers");
    assert_eq!(findings[1].operation, "operate");
    assert_eq!(findings[2].operation, "write variable");
    assert_eq!(findings[3].operation, "ReinitializeDevice");
}

#[test]
fn ignores_read_only_modbus_and_emits_critical_control_alerts() {
    let mut read = vec![0_u8; 8];
    read[5] = 2;
    read[7] = 3;
    assert!(industrial_policy::inspect(&industrial_packet("Modbus", 502, true, &read)).is_none());

    let mut dnp3 = vec![0_u8; 13];
    dnp3[..2].copy_from_slice(&[0x05, 0x64]);
    dnp3[12] = 0x0d;
    let mut security = SecurityEngine::default();
    security.update(&industrial_packet("DNP3", 20_000, true, &dnp3));
    assert!(security.ids_alerts.iter().any(|alert| {
        alert.signature == "Critical industrial control command" && alert.severity == Severity::Critical
    }));

    let mut write = vec![0_u8; 8];
    write[5] = 2;
    write[7] = 16;
    let mut security = SecurityEngine::default();
    security.update(&industrial_packet("Modbus", 502, true, &write));
    assert!(security
        .ids_alerts
        .iter()
        .any(|alert| alert.signature == "Industrial state-changing command"));
}

#[test]
fn industrial_policy_requires_a_complete_transport_and_matching_wire_port() {
    let mut modbus = [0_u8; 8];
    modbus[5] = 2;
    modbus[7] = 6;
    let valid = industrial_packet("Modbus", 502, true, &modbus);
    assert!(industrial_policy::inspect(&valid).is_some());

    let mut fragmented = valid.clone();
    for fragment_offset in [0x2000_u16, 1] {
        fragmented.bytes[20..22].copy_from_slice(&fragment_offset.to_be_bytes());
        assert!(industrial_policy::inspect(&fragmented).is_none());
    }
    let mut short = valid.clone();
    short.bytes[16..18].copy_from_slice(&60_u16.to_be_bytes());
    assert!(industrial_policy::inspect(&short).is_none());
    let mut wrong_port = valid.clone();
    wrong_port.bytes[36..38].copy_from_slice(&503_u16.to_be_bytes());
    assert!(industrial_policy::inspect(&wrong_port).is_none());
    let mut short_tcp_header = valid.clone();
    short_tcp_header.bytes[46] = 0x40;
    assert!(industrial_policy::inspect(&short_tcp_header).is_none());
    assert!(industrial_policy::inspect(&industrial_packet("Modbus", 502, false, &modbus)).is_none());
}

#[test]
fn industrial_policy_never_reads_trailing_ip_bytes_as_udp_payload() {
    let mut bacnet = [0_u8; 10];
    bacnet[0] = 0x81;
    bacnet[4] = 0x01;
    bacnet[9] = 15;
    let mut packet = industrial_packet("BACnet", 47_808, false, &bacnet);
    assert!(industrial_policy::inspect(&packet).is_some());
    for udp_length in [7_u16, 8, 19] {
        packet.bytes[38..40].copy_from_slice(&udp_length.to_be_bytes());
        assert!(industrial_policy::inspect(&packet).is_none());
    }
    assert!(industrial_policy::inspect(&industrial_packet("BACnet", 47_808, true, &bacnet)).is_none());
}

#[test]
fn industrial_alert_exposes_a_policy_hint_not_a_claim_of_execution() {
    let mut modbus = [0_u8; 8];
    modbus[5] = 2;
    modbus[7] = 6;
    let mut core = packrat_tui::engine::AnalysisCore::default();
    core.analyze(&industrial_packet("Modbus", 502, true, &modbus));
    let alert = core.alert_center.items.iter()
        .find(|alert| alert.title == "Industrial state-changing command").unwrap();
    let provenance = alert.provenance.as_ref().unwrap();
    assert_eq!(provenance.rule_id, "industrial.state_change");
    assert_eq!(provenance.confidence, packrat_tui::analysis::alert_provenance::EvidenceConfidence::Heuristic);
    assert!(provenance.verification_hint.contains("does not prove a state change"));
    assert_eq!(alert.packet_refs, [1]);
}
