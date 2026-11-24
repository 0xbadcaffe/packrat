use super::archive_fixture::{drain, finish, roll_history, start};
use super::tcp_probe;
use packrat_tui::storage::packet_archive::PacketArchive;

#[test]
fn opted_in_admin_fanout_archives_exact_pairs_and_the_timely_retry_after_rollover() {
    use packrat_tui::net::parser::parse_ethernet;

    let rule = "tcp.admin_service_response_fanout";
    let packet = |frame, host, reply, vlan, time| {
        let flags = if reply { 0x12 } else { 0x02 };
        let mut bytes = tcp_probe(frame, [10, 0, 1, host], 445, flags, time).bytes;
        let (src, dst) = if reply { ([10, 0, 1, host], [10, 0, 0, 9]) }
            else { ([10, 0, 0, 9], [10, 0, 1, host]) };
        bytes[26..30].copy_from_slice(&src);
        bytes[30..34].copy_from_slice(&dst);
        bytes[38..42].copy_from_slice(&100_u32.to_be_bytes());
        if reply {
            bytes[34..36].copy_from_slice(&445_u16.to_be_bytes());
            bytes[36..38].copy_from_slice(&50_000_u16.to_be_bytes());
            bytes[42..46].copy_from_slice(&101_u32.to_be_bytes());
        }
        bytes.splice(12..12, [0x81, 0, 0, vlan]);
        parse_ethernet(&bytes, frame, time)
    };
    for selected in [false, true] {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("archive");
        let rules = vec![if selected { rule } else { "icmp.address_sweep" }.into()];
        let mut app = start(&path, rules);
        app.inject_packet(packet(1, 8, false, 10, 1.0));
        let mut cited = Vec::new();
        for host in 1..=7_u8 {
            let frame = 2 * u64::from(host);
            cited.extend([packet(frame, host, false, 10, 2.0), packet(frame + 1, host, true, 10, 3.0)]);
        }
        for frame in &cited { app.inject_packet(frame.clone()); }
        app.inject_packet(packet(16, 8, false, 20, 9.0));
        cited.push(packet(17, 8, false, 10, 10.0));
        app.inject_packet(cited.last().unwrap().clone());
        let trigger = roll_history(&mut app, 18);
        cited.push(packet(trigger, 8, true, 10, 17.0));
        app.inject_packet(cited.last().unwrap().clone());
        finish(&mut app);

        let alert = app.query_core(|core| core.alert_center.items.iter().find(|alert|
            alert.provenance.as_ref().is_some_and(|provenance| provenance.rule_id == rule)).cloned()).unwrap().unwrap();
        assert_eq!(alert.packet_refs, cited.iter().map(|frame| frame.no).collect::<Vec<_>>());
        let scope = alert.capture_id.unwrap();
        let mut archive = PacketArchive::open_readonly(&path).unwrap();
        assert_eq!(archive.count().unwrap(), if selected { cited.len() as u64 } else { 0 });
        for frame in cited {
            assert_eq!(archive.packet_for_capture(&scope, frame.no).unwrap().map(|packet| packet.bytes),
                selected.then_some(frame.bytes));
        }
    }
}

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
fn syn_arrival_archive_keeps_cited_attempts_and_the_reordered_trigger() {
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
    assert_eq!(archive.count().unwrap(), refs.len() as u64);
    for frame in (1..=103).chain([trigger]) {
        assert_eq!(archive.packet_for_capture(&scope, frame).unwrap().is_some(),
            refs.contains(&frame));
    }
}

#[test]
fn opted_in_echo_sweeps_archive_only_cited_requests_for_the_same_family_and_vlan() {
    use super::{cases_3::ipv6_frame, ipv4_discovery_cases::discovery_packet};
    use packrat_tui::net::parser::parse_ethernet;

    let rule = "icmp.address_sweep";
    for ipv6 in [false, true] {
        for opt_in in [false, true] {
            let scratch = tempfile::tempdir().unwrap();
            let path = scratch.path().join("archive");
            let mut app = start(&path, opt_in.then(|| rule.into()).into_iter().collect());
            let echo = |frame, host: u8, v6, request, time| {
                let mut payload = [0_u8; 8];
                let mut packet = if v6 {
                    payload[0] = if request { 128 } else { 129 };
                    parse_ethernet(&ipv6_frame(host.into(), 58, &payload), frame, time)
                } else {
                    payload[0] = if request { 8 } else { 0 };
                    discovery_packet(frame, host, 1, &payload)
                };
                packet.timestamp = time;
                packet.vlan_id = Some(10);
                packet
            };
            let chosen = echo(3, 1, ipv6, true, 1.1);
            let mut other_vlan = echo(4, 12, ipv6, true, 2.0);
            other_vlan.vlan_id = Some(20);
            for packet in [echo(1, 1, ipv6, true, 1.0), echo(2, 1, ipv6, true, 0.9),
                chosen.clone(), other_vlan, echo(5, 12, !ipv6, true, 2.0), echo(6, 13, ipv6, false, 2.0)] {
                app.inject_packet(packet);
            }
            for host in 2..=11 {
                app.inject_packet(echo(u64::from(host) + 5, host, ipv6, true, 3.0));
            }
            let trigger = roll_history(&mut app, 17);
            app.inject_packet(echo(trigger, 12, ipv6, true, 2.5));
            finish(&mut app);

            let alert = app.query_core(|core| core.alert_center.items.iter().find(|alert|
                alert.provenance.as_ref().is_some_and(|p| p.rule_id == rule)).cloned()).unwrap().unwrap();
            let refs: Vec<_> = [3].into_iter().chain(7..=16).chain([trigger]).collect();
            assert_eq!(alert.packet_refs, refs);
            let scope = alert.capture_id.unwrap();
            let mut archive = PacketArchive::open_readonly(&path).unwrap();
            assert_eq!(archive.count().unwrap(), if opt_in { 12 } else { 0 });
            for frame in (1..=16).chain([trigger]) {
                assert_eq!(archive.packet_for_capture(&scope, frame).unwrap().is_some(), opt_in && refs.contains(&frame));
            }
            assert_eq!(archive.packet_for_capture(&scope, 3).unwrap().map(|saved| saved.bytes), opt_in.then_some(chosen.bytes));
        }
    }
}
