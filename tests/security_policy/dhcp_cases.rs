use super::*;
use packrat_tui::engine::AnalysisCore;
use packrat_tui::net::packet::CaptureMetadata;

const BURST: &str = "DHCP client identity burst";
const SERVER_CHANGE: &str = "DHCP server identity changed";

fn server_reply(frame: u64, kind: u8, observed_mac: u8, server: Option<u8>, timestamp: f64) -> Packet {
    let mut packet = dhcp_packet(frame, kind, [2, 0, 0, 0, 0, observed_mac], [2; 6],
        server.map(|last_octet| [10, 0, 0, last_octet]));
    packet.timestamp = timestamp;
    packet
}

fn tagged_dhcp(packet: Packet, provider: bool) -> Packet {
    let mut raw = packet.bytes;
    let tpid = if provider { 0x88a8_u16 } else { 0x8100_u16 };
    let tci = if packet.no % 2 == 0 { 0xb014_u16 } else { 20_u16 };
    raw.splice(12..12, [tpid, tci].into_iter().flat_map(u16::to_be_bytes));
    packrat_tui::net::parser::parse_ethernet(&raw, packet.no, packet.timestamp)
}

#[test]
fn dhcp_server_evidence_stays_on_the_observed_tag_path() {
    let mut core = AnalysisCore::default();
    for (no, server, provider) in [(1, 1, false), (2, 2, true), (3, 3, false), (4, 4, true)] {
        core.analyze(&tagged_dhcp(server_reply(no, 2, server, Some(server), no as f64), provider));
        if no < 3 {
            assert!(core.alert_center.items.iter().all(|alert| alert.title != SERVER_CHANGE));
        }
    }
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == SERVER_CHANGE).collect();
    assert_eq!(alerts.len(), 2);
    for (alert, frames, tag) in [(alerts[0], [1, 3], "0x8100"), (alerts[1], [2, 4], "0x88a8")] {
        assert_eq!(alert.packet_refs, frames);
        assert!(alert.detail.contains(tag));
    }
}

#[test]
fn dhcp_client_threshold_cannot_combine_tag_paths() {
    let mut core = AnalysisCore::default();
    for identity in 0..96_u8 {
        let frame = u64::from(identity) + 1;
        let provider = identity < 64 && identity % 2 == 1;
        core.analyze(&tagged_dhcp(discovery(frame, identity, 1.0), provider));
        if frame < 96 {
            assert!(core.alert_center.items.iter().all(|alert| alert.title != BURST));
        }
    }
    let alert = core.alert_center.items.iter().find(|alert| alert.title == BURST).unwrap();
    assert_eq!(alert.packet_refs, (1..=63).step_by(2).chain(65..=96).collect::<Vec<_>>());
    assert!(alert.detail.contains("0x8100"));
}

#[test]
fn dhcp_server_change_retains_both_replies_and_uses_advertised_identifier() {
    let mut core = AnalysisCore::default();
    core.analyze(&server_reply(1, 2, 1, Some(1), 1.0));
    core.analyze(&server_reply(2, 2, 2, Some(1), 2.0));
    core.analyze(&server_reply(3, 5, 3, None, 3.0));
    assert!(core.alert_center.items.iter().all(|alert| alert.title != SERVER_CHANGE));

    core.analyze(&server_reply(4, 2, 2, Some(2), 4.0));
    core.analyze(&server_reply(5, 5, 5, Some(2), 5.0));
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == SERVER_CHANGE).collect();
    assert_eq!(alerts.len(), 1);
    let alert = alerts[0];
    assert_eq!(alert.packet_refs, [2, 4]);
    assert_eq!(alert.severity, "MEDIUM");
    assert!(alert.detail.contains("10.0.0.2") && alert.detail.contains("10.0.0.1"));
    assert!(alert.detail.contains("Authorization is unknown"));
    assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "dhcp.new_server_identifier");
}

#[test]
fn dhcp_server_comparison_ignores_old_and_other_vlan_observations() {
    let mut engine = SecurityEngine::default();
    engine.update(&server_reply(1, 2, 1, Some(1), 1.0));
    let mut other = server_reply(2, 2, 2, Some(2), 2.0);
    other.outer_vlan_id = Some(100);
    engine.update(&other);
    engine.update(&server_reply(3, 2, 3, Some(3), 3602.0));
    engine.update(&server_reply(4, 2, 4, Some(4), 2.0));
    assert!(engine.ids_alerts.iter().all(|alert| alert.signature != SERVER_CHANGE));

    let result = engine.inspect(&server_reply(5, 5, 5, Some(4), 3603.0));
    let finding = result.ids.iter().find(|finding| finding.alert.signature == SERVER_CHANGE).unwrap();
    assert_eq!(finding.related_packets, [3]);
    assert!(finding.alert.detail.contains("DHCP ACK"));
}

#[test]
fn dhcp_server_comparison_prefers_the_latest_frame_at_the_same_timestamp() {
    let mut engine = SecurityEngine::default();
    engine.update(&server_reply(1, 2, 1, Some(250), 1.0));
    engine.update(&server_reply(2, 2, 2, Some(1), 1.0));
    let result = engine.inspect(&server_reply(3, 5, 3, Some(2), 1.0));
    let finding = result.ids.iter().find(|finding| finding.alert.signature == SERVER_CHANGE).unwrap();
    assert_eq!(finding.related_packets, [2]);
    assert!(finding.alert.detail.contains("previously observed 10.0.0.1"));
}

#[test]
fn dhcp_relay_replies_compare_servers_only_within_the_advertised_relay_context() {
    let a = [192, 0, 2, 1];
    let b = [192, 0, 2, 2];
    let mut engine = SecurityEngine::default();
    engine.update(&server_reply(1, 2, 1, Some(1), 1.0));
    engine.update(&dhcp_fixture::relayed_packet(server_reply(2, 2, 2, Some(2), 2.0), a));
    engine.update(&dhcp_fixture::relayed_packet(server_reply(3, 2, 3, Some(3), 3.0), b));
    let mut inconsistent = dhcp_fixture::relayed_packet(server_reply(4, 5, 4, Some(4), 4.0), a);
    inconsistent.bytes[30..34].copy_from_slice(&b);
    engine.update(&inconsistent);
    assert!(engine.ids_alerts.iter().all(|alert| alert.signature != SERVER_CHANGE));

    let result = engine.inspect(&dhcp_fixture::relayed_packet(server_reply(5, 5, 4, Some(4), 5.0), a));
    let finding = result.ids.iter().find(|finding| finding.alert.signature == SERVER_CHANGE).unwrap();
    assert_eq!(finding.related_packets, [2]);
    assert!(finding.alert.detail.contains("advertised relay address 192.0.2.1"));
    assert!(finding.alert.detail.contains("previously observed 10.0.0.2"));
}

fn discovery(frame: u64, identity: u8, timestamp: f64) -> Packet {
    let mac = [2, 0, 0, 0, 0, identity];
    let mut packet = dhcp_packet(frame, 1, mac, mac, None);
    packet.timestamp = timestamp;
    packet
}

fn append_options(packet: &mut Packet, options: &[u8]) {
    let raw = &mut packet.bytes;
    assert_eq!(raw.pop(), Some(255));
    raw.extend_from_slice(options);
    raw.push(255);
    let ip_len = (raw.len() - 14) as u16;
    let udp_len = ip_len - 20;
    raw[16..18].copy_from_slice(&ip_len.to_be_bytes());
    raw[38..40].copy_from_slice(&udp_len.to_be_bytes());
}

#[test]
fn dhcp_server_comparison_recovers_a_split_server_identifier() {
    let mut engine = SecurityEngine::default();
    engine.update(&server_reply(1, 2, 1, Some(1), 1.0));
    let mut reply = server_reply(2, 2, 2, None, 2.0);
    append_options(&mut reply, &[52, 1, 1, 54, 2, 10, 0]);
    reply.bytes[150..155].copy_from_slice(&[54, 2, 0, 2, 255]);
    let result = engine.inspect(&reply);
    let finding = result.ids.iter().find(|finding| finding.alert.signature == SERVER_CHANGE).unwrap();
    assert_eq!(finding.related_packets, [1]);
    assert!(finding.alert.detail.contains("advertised server identifier 10.0.0.2"));
}

#[test]
fn dhcp_identity_burst_deduplicates_different_encodings_of_the_same_client() {
    let mut engine = SecurityEngine::default();
    for identity in 0..62 {
        engine.update(&discovery(u64::from(identity) + 1, identity, 1.0));
    }
    let mut plain = discovery(63, 62, 1.0);
    append_options(&mut plain, &[61, 3, 0, b'x', b'y']);
    engine.update(&plain);

    let mut split = discovery(64, 63, 1.0);
    append_options(&mut split, &[61, 2, 0, b'x', 61, 1, b'y']);
    engine.update(&split);
    assert!(engine.ids_alerts.iter().all(|alert| alert.signature != BURST));

    let mut overloaded = discovery(65, 64, 1.0);
    append_options(&mut overloaded, &[52, 1, 3, 61, 1, 0]);
    let file = 42 + 108;
    let sname = 42 + 44;
    overloaded.bytes[file..file + 4].copy_from_slice(&[61, 1, b'x', 255]);
    overloaded.bytes[sname..sname + 4].copy_from_slice(&[61, 1, b'y', 255]);
    engine.update(&overloaded);
    assert!(engine.ids_alerts.iter().all(|alert| alert.signature != BURST));

    let result = engine.inspect(&discovery(66, 65, 2.0));
    let finding = result.ids.iter().find(|finding| finding.alert.signature == BURST).unwrap();
    assert!(finding.related_packets.contains(&63));
    assert!(finding.related_packets.contains(&66));
    assert!(!finding.related_packets.contains(&64));
    assert!(!finding.related_packets.contains(&65));
}

#[test]
fn dhcp_identity_burst_keeps_one_frame_per_identity_and_explains_uncertainty() {
    let mut core = AnalysisCore::default();
    for frame in 1..=80 {
        core.analyze(&discovery(frame, 0, 1.0));
    }
    assert!(core.alert_center.items.iter().all(|alert| alert.title != BURST));
    for identity in 1..=63 {
        core.analyze(&discovery(80 + u64::from(identity), identity, 2.0));
    }
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == BURST).collect();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].severity, "MEDIUM");
    assert!(alerts[0].detail.contains("lease exhaustion was not observed"));
    assert_eq!(alerts[0].packet_refs, std::iter::once(1).chain(81..=143).collect::<Vec<_>>());
    let rule = alerts[0].provenance.as_ref().unwrap();
    assert_eq!(rule.rule_id, "dhcp.discover_identity_burst");
    assert_eq!(rule.revision, 5);
}

#[test]
fn relayed_discovery_counts_distinct_clients_without_combining_relay_contexts() {
    let a = [192, 0, 2, 1];
    let b = [192, 0, 2, 2];
    let mut engine = SecurityEngine::default();
    for identity in 0..64_u8 {
        let relay = if identity < 32 { a } else { b };
        engine.update(&dhcp_fixture::relayed_packet(
            discovery(u64::from(identity) + 1, identity, 1.0), relay,
        ));
    }
    assert!(engine.ids_alerts.iter().all(|alert| alert.signature != BURST));
    for identity in 64..95_u8 {
        engine.update(&dhcp_fixture::relayed_packet(
            discovery(u64::from(identity) + 1, identity, 2.0), a,
        ));
    }
    let result = engine.inspect(&dhcp_fixture::relayed_packet(discovery(96, 95, 2.0), a));
    let finding = result.ids.iter().find(|finding| finding.alert.signature == BURST).unwrap();
    assert_eq!(finding.related_packets, (1..=32).chain(65..=96).collect::<Vec<_>>());
    assert!(finding.alert.detail.contains("advertised relay address 192.0.2.1"));
}

#[rstest]
#[case(true)]
#[case(false)]
fn dhcp_observations_do_not_combine_interfaces_or_outer_vlans(#[case] separate_interfaces: bool) {
    let mut engine = SecurityEngine::default();
    for identity in 0..64 {
        let mut packet = discovery(u64::from(identity) + 1, identity, 1.0);
        if separate_interfaces {
            packet.capture = Some(CaptureMetadata {
                timestamp: None, wire_length: packet.bytes.len() as u32,
                captured_length: packet.bytes.len() as u32, link_type: 1,
                section_id: 0, interface_id: u32::from(identity % 2),
                interface_name: None, comments: Vec::new(),
            });
        } else {
            packet.outer_vlan_id = Some(u16::from(identity % 2) + 100);
        }
        engine.update(&packet);
    }
    assert!(engine.ids_alerts.iter().all(|alert| alert.signature != BURST));
}

#[test]
fn dhcp_burst_uses_capture_window_and_rearms_after_distinct_clients_expire() {
    let mut engine = SecurityEngine::default();
    for identity in 0..64 {
        engine.update(&discovery(u64::from(identity) + 1, identity, 1.0));
    }
    engine.update(&discovery(65, 100, 11.1));
    for identity in 0..64 {
        engine.update(&discovery(u64::from(identity) + 66, identity, 1.0));
    }
    assert_eq!(engine.ids_alerts.iter().filter(|alert| alert.signature == BURST).count(), 1);
    for identity in 0..63 {
        let result = engine.inspect(&discovery(u64::from(identity) + 130, identity, 11.2));
        if identity == 62 {
            let finding = result.ids.iter().find(|finding| finding.alert.signature == BURST).unwrap();
            assert_eq!(finding.related_packets, std::iter::once(65).chain(130..=192).collect::<Vec<_>>());
        } else {
            assert!(result.ids.iter().all(|finding| finding.alert.signature != BURST));
        }
    }
}

#[rstest]
#[case("ipv4 total length")]
#[case("capture truncation")]
#[case("udp length")]
#[case("fragment offset")]
#[case("more fragments")]
#[case("bootp operation")]
#[case("udp direction")]
#[case("hardware length")]
#[case("missing end option")]
#[case("duplicate message type")]
#[case("short client identifier")]
#[case("invalid overloaded options")]
fn dhcp_identity_burst_ignores_incomplete_or_inconsistent_observations(#[case] defect: &str) {
    const IP: usize = 14;
    const UDP: usize = IP + 20;
    const BOOTP: usize = UDP + 8;
    let mut engine = SecurityEngine::default();
    for identity in 0..63 {
        engine.update(&discovery(u64::from(identity) + 1, identity, 1.0));
    }
    let mut candidate = discovery(64, 63, 2.0);
    let raw = &mut candidate.bytes;
    match defect {
        "ipv4 total length" => raw[IP + 2..IP + 4].copy_from_slice(&28_u16.to_be_bytes()),
        "capture truncation" => { raw.pop(); }
        "udp length" => {
            let length = u16::from_be_bytes(raw[UDP + 4..UDP + 6].try_into().unwrap());
            raw[UDP + 4..UDP + 6].copy_from_slice(&(length + 1).to_be_bytes());
        }
        "fragment offset" => raw[IP + 7] = 1,
        "more fragments" => raw[IP + 6] = 0x20,
        "bootp operation" => raw[BOOTP] = 2,
        "udp direction" => {
            raw[UDP + 1] = 67;
            raw[UDP + 3] = 68;
            raw[BOOTP] = 2;
        }
        "hardware length" => raw[BOOTP + 2] = 17,
        "missing end option" => *raw.last_mut().unwrap() = 0,
        "duplicate message type" => {
            raw.pop();
            raw.extend_from_slice(&[53, 1, 1, 255]);
            let ip_len = (raw.len() - IP) as u16;
            let udp_len = (raw.len() - UDP) as u16;
            raw[IP + 2..IP + 4].copy_from_slice(&ip_len.to_be_bytes());
            raw[UDP + 4..UDP + 6].copy_from_slice(&udp_len.to_be_bytes());
        }
        "short client identifier" => append_options(&mut candidate, &[61, 1, 0]),
        "invalid overloaded options" => append_options(&mut candidate, &[52, 1, 1]),
        _ => unreachable!(),
    }
    engine.update(&candidate);
    assert!(engine.ids_alerts.iter().all(|alert| alert.signature != BURST), "{defect}");
    let mut valid = discovery(65, 63, 2.0);
    valid.bytes.extend_from_slice(&[0; 4]); // Link-layer trailer outside the IP datagram.
    let result = engine.inspect(&valid);
    let finding = result.ids.iter().find(|finding| finding.alert.signature == BURST).unwrap();
    assert!(finding.related_packets.contains(&65));
    assert!(!finding.related_packets.contains(&64));
}
