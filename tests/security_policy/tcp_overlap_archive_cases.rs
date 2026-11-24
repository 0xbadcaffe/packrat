use super::ipv4_tcp_packet;
use super::archive_fixture::{finish, roll_history, start};
use packrat_tui::net::packet::{CaptureMetadata, CaptureTimestamp, TimestampResolution};
use packrat_tui::storage::packet_archive::PacketArchive;

#[test]
fn tcp_overlap_archive_recovers_original_wraparound_segment_without_other_vlans() {
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("archive");
    let mut app = start(&path, Vec::new());
    let compare = |frame, vlan, bytes: &[u8]| {
        let mut packet = ipv4_tcp_packet(frame, u32::MAX - 2, 0x18, bytes);
        packet.vlan_id = Some(vlan);
        packet
    };
    let original = compare(1, 10, b"ABCD");
    app.inject_packet(original.clone());
    app.inject_packet(compare(2, 10, b"ABCD"));
    app.inject_packet(compare(3, 20, b"ABCE"));
    let mut independent = ipv4_tcp_packet(4, 7, 0x18, b"ordinary data");
    independent.timestamp = 500.0;
    let length = independent.bytes.len() as u32;
    independent.capture = Some(CaptureMetadata {
        timestamp: Some(CaptureTimestamp {
            ticks: 500, resolution: TimestampResolution::Decimal(0), offset_seconds: 0,
        }),
        captured_length: length,
        wire_length: length,
        link_type: 1,
        section_id: 0,
        interface_id: 1,
        interface_name: None,
        comments: Vec::new(),
    });
    app.inject_packet(independent);
    let trigger = roll_history(&mut app, 5);
    let mut incoming = ipv4_tcp_packet(trigger, 0, 0x18, b"X");
    incoming.vlan_id = Some(10);
    incoming.timestamp = 0.5;
    app.inject_packet(incoming.clone());
    finish(&mut app);

    let alert = app.query_core(|core| core.alert_center.items.iter().find(|alert|
        alert.provenance.as_ref().is_some_and(|p| p.rule_id == "tcp.conflicting_retransmission")).cloned()).unwrap().unwrap();
    assert_eq!(alert.packet_refs, [1, trigger]);
    let scope = alert.capture_id.unwrap();
    let mut archive = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(archive.count().unwrap(), 2);
    for packet in [original, incoming] {
        assert_eq!(archive.packet_for_capture(&scope, packet.no).unwrap().unwrap().bytes, packet.bytes);
    }
}
