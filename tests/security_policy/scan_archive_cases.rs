use super::archive_fixture::{drain, finish, roll_history, start};
use super::tcp_probe;
use packrat_tui::storage::packet_archive::PacketArchive;

#[test]
fn scan_archive_keeps_only_the_selected_probes_and_matched_replies_after_rollover() {
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("archive");
    let mut app = start(&path, Vec::new());
    let syn = |frame, host, time| {
        let mut packet = tcp_probe(frame, [192, 0, 2, host], 443, 0x02, time);
        packet.vlan_id = Some(10);
        packet
    };
    let first = syn(1, 1, 1.0);
    let mut reply = first.clone();
    reply.no = 2;
    reply.timestamp = 1.1;
    std::mem::swap(&mut reply.src, &mut reply.dst);
    std::mem::swap(&mut reply.src_port, &mut reply.dst_port);
    for index in 0..4 { reply.bytes.swap(26 + index, 30 + index); }
    for index in 0..2 { reply.bytes.swap(34 + index, 36 + index); }
    reply.bytes[38..42].copy_from_slice(&200_u32.to_be_bytes());
    reply.bytes[42..46].copy_from_slice(&2_u32.to_be_bytes());
    reply.bytes[47] = 0x12;
    let mut ack = first.clone();
    ack.no = 3;
    ack.timestamp = 1.2;
    ack.bytes[38..42].copy_from_slice(&2_u32.to_be_bytes());
    ack.bytes[42..46].copy_from_slice(&201_u32.to_be_bytes());
    ack.bytes[47] = 0x10;
    let replacement = syn(5, 2, 1.4);
    let mut retry = replacement.clone();
    retry.no = 6;
    let mut other_vlan = syn(7, 12, 2.0);
    other_vlan.vlan_id = Some(20);
    for packet in [first.clone(), reply.clone(), ack.clone(), syn(4, 2, 1.3), replacement, retry, other_vlan] {
        app.inject_packet(packet);
    }
    for host in 3..=11_u8 {
        app.inject_packet(syn(u64::from(host) + 5, host, 3.0));
    }
    let trigger = roll_history(&mut app, 17);
    app.inject_packet(syn(trigger, 12, 2.5));
    finish(&mut app);

    let alert = app.query_core(|core| core.alert_center.items.iter().find(|alert|
        alert.provenance.as_ref().is_some_and(|p| p.rule_id == "scan.horizontal")).cloned()).unwrap().unwrap();
    let expected: Vec<_> = [1, 2, 3, 5].into_iter().chain(8..=16).chain([trigger]).collect();
    assert_eq!(alert.packet_refs, expected);
    let scope = alert.capture_id.unwrap();
    let mut archive = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(archive.count().unwrap(), expected.len() as u64);
    for frame in expected {
        assert!(archive.packet_for_capture(&scope, frame).unwrap().is_some());
    }
    for packet in [first, reply, ack] {
        assert_eq!(archive.packet_for_capture(&scope, packet.no).unwrap().unwrap().bytes, packet.bytes);
    }
}

#[test]
fn syn_arrival_archive_keeps_newest_cited_attempts_and_the_reordered_trigger() {
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("archive");
    let mut app = start(&path, Vec::new());
    let syn = |frame, vlan, port, time| {
        let mut packet = tcp_probe(frame, [192, 0, 2, 4], port, 0x02, time);
        packet.vlan_id = Some(vlan);
        packet
    };
    app.inject_packet(syn(1, 10, 443, 3.25));
    for frame in 2..=100 {
        app.inject_packet(syn(frame, 10, 443, 5.0));
        drain(&mut app);
    }
    let mut retry = syn(100, 10, 443, 5.0);
    retry.no = 101;
    app.inject_packet(retry);
    app.inject_packet(syn(102, 20, 443, 5.0));
    app.inject_packet(syn(103, 10, 444, 5.0));
    let trigger = roll_history(&mut app, 104);
    app.inject_packet(syn(trigger, 10, 443, 4.5));
    finish(&mut app);

    let alert = app.query_core(|core| core.alert_center.items.iter().find(|alert|
        alert.provenance.as_ref().is_some_and(|p| p.rule_id == "tcp.syn_arrival_spike")).cloned()).unwrap().unwrap();
    let refs: Vec<_> = (2..=100).chain([trigger]).collect();
    assert_eq!(alert.packet_refs, refs);
    let scope = alert.capture_id.unwrap();
    let mut archive = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(archive.count().unwrap(), 32);
    for frame in (1..=103).chain([trigger]) {
        assert_eq!(archive.packet_for_capture(&scope, frame).unwrap().is_some(),
            (70..=100).contains(&frame) || frame == trigger);
    }
}
