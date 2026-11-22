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

fn dnp3_header_fixture(operation: u8) -> [u8; 15] {
    // Header-only test records contain no control objects.
    let [crc_lo, crc_hi] = match operation {
        1 => [0x6d, 0xa0],
        2 => [0x8f, 0xfa],
        3 => [0xd1, 0xcc],
        4 => [0x4b, 0x4f],
        _ => unreachable!(),
    };
    [0x05, 0x64, 8, 0xc4, 1, 0, 2, 0, 0x39, 0x0d, 0xc0, 0xc0, operation, crc_lo, crc_hi]
}

fn bacnet_header_fixture(service: u8) -> [u8; 11] {
    // The test fixture has a placeholder byte, not an encoded service argument.
    [0x81, 0x0a, 0, 11, 1, 0x04, 0, 0, 1, service, 0]
}

fn s7_job_header_fixture(operation: u8) -> [u8; 18] {
    // Framing-only fixture: the function marker has no operation arguments.
    [3, 0, 0, 18, 2, 0xf0, 0x80, 0x32, 1, 0, 0, 0, 1, 0, 1, 0, 0, operation]
}

#[test]
fn identifies_state_changing_modbus_dnp3_s7_and_bacnet_operations() {
    let mut modbus = vec![0_u8; 8];
    modbus[5] = 2;
    modbus[7] = 16;

    let dnp3 = dnp3_header_fixture(4);

    let s7 = s7_job_header_fixture(5);

    let bacnet = bacnet_header_fixture(20);

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

    let dnp3 = dnp3_header_fixture(4);
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
    let bacnet = bacnet_header_fixture(15);
    let mut packet = industrial_packet("BACnet", 47_808, false, &bacnet);
    assert!(industrial_policy::inspect(&packet).is_some());
    for udp_length in [7_u16, 8, 20] {
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
    assert_eq!(provenance.revision, 8);
    assert_eq!(provenance.confidence, packrat_tui::analysis::alert_provenance::EvidenceConfidence::Heuristic);
    assert!(provenance.verification_hint.contains("does not prove a state change"));
    assert_eq!(alert.packet_refs, [1]);
}

#[test]
fn bacnet_policy_accepts_only_direct_unsegmented_confirmed_requests() {
    let inspect = |payload: &[u8]| industrial_policy::inspect(&industrial_packet("BACnet", 47_808, false, payload));
    let request = bacnet_header_fixture(15);
    assert_eq!(inspect(&request).unwrap().operation, "WriteProperty");
    assert!(inspect(&bacnet_header_fixture(12)).is_none());
    for (offset, value) in [
        (1, 0), (1, 4), (1, 11), (3, 10), (3, 12), (4, 2),
        (5, 0x84), (5, 0x24), (5, 0x0c), (6, 0x08), (6, 0x04), (6, 0x20),
    ] {
        let mut other = request;
        other[offset] = value;
        assert!(inspect(&other).is_none(), "offset {offset}, value {value}");
    }
    for end in 0..request.len() {
        assert!(inspect(&request[..end]).is_none());
    }
}

#[test]
fn s7_policy_requires_complete_tpkt_job_framing() {
    let inspect = |payload: &[u8]| industrial_policy::inspect(&industrial_packet("S7comm", 102, true, payload));
    let request = s7_job_header_fixture(5);
    assert_eq!(inspect(&request).unwrap().operation, "write variable");
    let read = s7_job_header_fixture(4);
    assert!(inspect(&read).is_none());
    let mut coalesced = read.to_vec();
    coalesced.extend(request);
    assert_eq!(inspect(&coalesced).unwrap().operation, "write variable");

    for (offset, value) in [
        (0, 2), (1, 1), (3, 6), (3, 17), (3, 19), (4, 3), (5, 0xd0),
        (6, 0), (7, 0), (8, 3), (14, 0), (14, 2), (16, 1),
    ] {
        let mut other = request;
        other[offset] = value;
        assert!(inspect(&other).is_none(), "offset {offset}, value {value}");
    }
    for end in 0..request.len() {
        assert!(inspect(&request[..end]).is_none());
    }
}

#[test]
fn modbus_policy_uses_complete_request_boundaries_and_ignores_replies() {
    let write_like = [0, 2, 0, 0, 0, 2, 1, 6];
    let read_only = [0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1];
    let inspect = |payload: &[u8]| industrial_policy::inspect(&industrial_packet("Modbus", 502, true, payload));
    assert!(inspect(&read_only).is_none());
    let mut coalesced = read_only.to_vec();
    coalesced.extend_from_slice(&write_like);
    assert_eq!(inspect(&coalesced).unwrap().operation, "write single register");

    let mut malformed = write_like;
    for length in [0_u16, 1, 3] {
        malformed[4..6].copy_from_slice(&length.to_be_bytes());
        assert!(inspect(&malformed).is_none());
    }
    malformed = write_like;
    malformed[3] = 1;
    assert!(inspect(&malformed).is_none());
    let mut overlong = write_like.to_vec();
    overlong.resize(261, 0);
    overlong[5] = 255;
    assert!(inspect(&overlong).is_none());
    for end in 0..write_like.len() {
        assert!(inspect(&write_like[..end]).is_none());
    }

    let mut reply = industrial_packet("Modbus", 502, true, &write_like);
    reply.bytes[34..36].copy_from_slice(&502_u16.to_be_bytes());
    reply.bytes[36..38].copy_from_slice(&50_000_u16.to_be_bytes());
    std::mem::swap(&mut reply.src_port, &mut reply.dst_port);
    assert!(industrial_policy::inspect(&reply).is_none());
}

#[test]
fn modbus_split_evidence_uses_the_shared_tcp_stream_without_duplicate_alerts() {
    use packrat_tui::engine::AnalysisCore;
    let segment = |number: u64, sequence: u32, flags: u8, payload: &[u8]| {
        let mut packet = industrial_packet("Modbus", 502, true, payload);
        packet.no = number;
        packet.timestamp = number as f64;
        packet.bytes[38..42].copy_from_slice(&sequence.to_be_bytes());
        packet.bytes[47] = flags;
        packet
    };
    let message = [0, 2, 0, 0, 0, 2, 1, 6];
    let syn = segment(1, 100, 0x02, &[]);
    let tail = segment(2, 106, 0x18, &message[5..]);
    let head = segment(3, 101, 0x18, &message[..5]);
    let rule = |item: &&packrat_tui::analysis::alert_center::AlertItem| {
        item.title == "Industrial state-changing command"
    };
    let mut core = AnalysisCore::default();
    core.analyze(&syn);
    core.analyze(&tail);
    assert!(core.alert_center.items.iter().find(rule).is_none());
    core.analyze(&head);
    let alert = core.alert_center.items.iter().find(rule).unwrap();
    assert_eq!(alert.packet_no, 3);
    assert_eq!(alert.packet_refs, [2, 3]);
    core.analyze(&segment(4, 101, 0x18, &message[..5]));
    assert_eq!(core.alert_center.items.iter().find(rule).unwrap().hit_count, 1);

    let mut unanchored = AnalysisCore::default();
    unanchored.analyze(&head);
    unanchored.analyze(&tail);
    assert!(unanchored.alert_center.items.iter().find(rule).is_none());

    let mut scoped = AnalysisCore::default();
    scoped.analyze(&syn);
    scoped.analyze(&tail);
    let mut unrelated = head;
    unrelated.vlan_id = Some(10);
    scoped.analyze(&unrelated);
    assert!(scoped.alert_center.items.iter().find(rule).is_none());
}

#[test]
fn anchored_modbus_does_not_reinterpret_a_continuation_or_retransmission() {
    use packrat_tui::engine::AnalysisCore;
    let segment = |number: u64, sequence: u32, flags: u8, payload: &[u8]| {
        let mut packet = industrial_packet("Modbus", 502, true, payload);
        packet.no = number;
        packet.timestamp = number as f64;
        packet.bytes[38..42].copy_from_slice(&sequence.to_be_bytes());
        packet.bytes[47] = flags;
        packet
    };
    let write_like = [0, 2, 0, 0, 0, 2, 1, 6];
    let read_prefix = [0, 1, 0, 0, 0, 10, 1, 3];
    let rule = |item: &&packrat_tui::analysis::alert_center::AlertItem| {
        item.title == "Industrial state-changing command"
    };

    let mut core = AnalysisCore::default();
    core.analyze(&segment(1, 100, 0x02, &[]));
    core.analyze(&segment(2, 101, 0x18, &read_prefix));
    core.analyze(&segment(3, 109, 0x18, &write_like));
    assert!(core.alert_center.items.iter().find(rule).is_none());

    core.analyze(&segment(4, 117, 0x18, &write_like));
    core.analyze(&segment(5, 117, 0x18, &write_like));
    let alert = core.alert_center.items.iter().find(rule).unwrap();
    assert_eq!(alert.packet_refs, [4]);
    assert_eq!(alert.hit_count, 1);
}

#[test]
fn industrial_alerts_group_only_the_same_operation_transport_and_scope() {
    use packrat_tui::engine::AnalysisCore;
    use packrat_tui::net::packet::{CaptureMetadata, CaptureTimestamp, TimestampResolution};
    let packet = |no: u64, tcp, interface_id, vlan, operation| {
        let payload = dnp3_header_fixture(operation);
        let mut packet = industrial_packet("DNP3", 20_000, tcp, &payload);
        packet.no = no;
        packet.timestamp = no as f64;
        packet.vlan_id = Some(vlan);
        packet.capture = Some(CaptureMetadata {
            timestamp: Some(CaptureTimestamp { ticks: no, resolution: TimestampResolution::Decimal(0), offset_seconds: 0 }),
            captured_length: packet.bytes.len() as u32,
            wire_length: packet.bytes.len() as u32,
            link_type: 1,
            interface_id,
            section_id: 0,
            interface_name: None,
            comments: Vec::new(),
        });
        packet
    };
    let mut core = AnalysisCore::default();
    for input in [
        packet(1, true, 0, 10, 2),
        packet(2, false, 0, 10, 2),
        packet(3, true, 0, 20, 2),
        packet(4, true, 1, 10, 2),
        packet(5, true, 0, 10, 3),
        packet(6, true, 0, 10, 2),
    ] {
        core.analyze(&input);
    }
    let alerts: Vec<_> = core.alert_center.items.iter()
        .filter(|alert| alert.title == "Industrial state-changing command").collect();
    assert_eq!(alerts.len(), 5);
    assert_eq!(alerts[0].packet_refs, [1, 6]);
    assert_eq!(alerts[0].hit_count, 2);
    assert_eq!(alerts[0].flow.unwrap().transport, packrat_tui::analysis::alert_center::AlertTransport::Tcp);
    assert!(alerts[0].detail.contains("10.0.0.5:50000 to 10.0.0.10:20000"));
    assert!(alerts[0].detail.contains("capture section 0, interface 0, VLAN 10"));
    assert!(alerts[2].detail.contains("VLAN 20"));
    assert!(alerts[3].detail.contains("interface 1, VLAN 10"));
    assert_eq!(alerts[1].flow.unwrap().transport, packrat_tui::analysis::alert_center::AlertTransport::Udp);
    assert!(alerts[2..].iter().all(|alert| alert.packet_refs.len() == 1 && alert.hit_count == 1));
}

#[test]
fn dnp3_policy_requires_valid_checksums_and_a_complete_application_header() {
    let check = |payload: &[u8]| industrial_policy::inspect(&industrial_packet("DNP3", 20_000, false, payload));
    let valid = dnp3_header_fixture(4);
    assert_eq!(check(&valid).unwrap().operation, "operate");
    assert!(check(&dnp3_header_fixture(1)).is_none());
    for end in 0..valid.len() {
        assert!(check(&valid[..end]).is_none());
    }
    for index in [8, 13] {
        let mut damaged = valid;
        damaged[index] ^= 1;
        assert!(check(&damaged).is_none());
    }
    let mut continuation = valid;
    continuation[10] = 0x80;
    continuation[13..].copy_from_slice(&[0x24, 0xc3]);
    assert!(check(&continuation).is_none());

    let mut two_blocks = vec![0x05, 0x64, 22, 0xc4, 1, 0, 2, 0, 0xfd, 0x84, 0xc0, 0xc0, 4];
    two_blocks.extend([0; 13]);
    two_blocks.extend([0x71, 0x38, 0, 0xff, 0xff]);
    assert!(check(&two_blocks).is_some());
    *two_blocks.last_mut().unwrap() ^= 1;
    assert!(check(&two_blocks).is_none());
}
