use super::*;
use packrat_tui::app::App;
use packrat_tui::engine::worker::WorkerLimits;
use packrat_tui::net::parser::parse_ethernet;
use packrat_tui::storage::packet_archive::{ArchiveLimits, ArchiveWorker, PacketArchive};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

fn drain(app: &mut App) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !app.analysis_idle() {
        app.poll_analysis();
        assert!(Instant::now() < deadline, "analysis did not drain");
        std::thread::yield_now();
    }
}

fn noise(app: &mut App, first: u64, time: f64) -> u64 {
    let trigger = first + WorkerLimits::default().history_packets as u64 + 1;
    for no in first..trigger {
        app.inject_packet(parse_ethernet(&[0; 14], no, time));
        drain(app);
    }
    app.packets.clear();
    trigger
}

fn udp(no: u64, reply: bool, resolver: &str, vlan: u8, timestamp: f64) -> Packet {
    let (source, destination) = if reply { (resolver, "10.0.0.5") } else { ("10.0.0.5", resolver) };
    let mut wire = dns_packet(no, reply, source, destination, 14, "audit.test").bytes;
    wire[26..30].copy_from_slice(&source.parse::<Ipv4Addr>().unwrap().octets());
    wire[30..34].copy_from_slice(&destination.parse::<Ipv4Addr>().unwrap().octets());
    if vlan > 0 { wire.splice(12..12, [0x81, 0, 0, vlan]); }
    parse_ethernet(&wire, no, timestamp)
}

fn start_app(archive_path: &std::path::Path, rules: Vec<String>) -> App {
    let mut app = App::new_for_test();
    let archive = ArchiveWorker::open_alert_evidence(archive_path, ArchiveLimits::default()).unwrap();
    app.set_packet_archive_with_rules(archive, rules).unwrap();
    app.start_background_analysis().unwrap();
    app
}

fn finish_app(app: &mut App, rule: &str, expected: &[u64]) -> String {
    drain(app);
    app.stop_background_analysis().unwrap();
    app.packet_archive.as_mut().unwrap().finish().unwrap();
    let alert = app.query_core(|core| core.alert_center.items.iter().find(|alert|
        alert.provenance.as_ref().is_some_and(|p| p.rule_id == rule)).cloned()).unwrap().unwrap();
    let mut frames = alert.packet_refs;
    frames.sort_unstable();
    assert_eq!(frames, expected);
    alert.capture_id.unwrap()
}

#[test]
fn competing_udp_dns_archives_query_and_both_replies_after_rollover() {
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("archive");
    let mut app = start_app(&path, Vec::new());
    for (no, reply, vlan) in [(1, false, 10), (2, false, 10), (3, true, 10), (4, false, 20), (5, true, 20)] {
        app.inject_packet(udp(no, reply, "10.0.0.53", vlan, no as f64));
    }
    drain(&mut app);
    let trigger = noise(&mut app, 6, 6.0);
    app.inject_packet(udp(trigger, true, "10.0.0.54", 10, 7.0));
    let scope = finish_app(&mut app, "dns.competing_responders", &[1, 3, trigger]);

    let mut archive = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(archive.count().unwrap(), 3);
    for frame in [1, 3, trigger] {
        assert!(archive.packet_for_capture(&scope, frame).unwrap().is_some());
    }
    for unrelated in [2, 4, 5] {
        assert!(archive.packet_for_capture(&scope, unrelated).unwrap().is_none());
    }
}

#[test]
fn dns_conflict_archives_latest_retry_when_it_kept_an_old_query_eligible() {
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("archive");
    let mut app = start_app(&path, Vec::new());
    let resolver = "10.0.0.53";
    for (no, timestamp) in [(1, 1.0), (2, 8.0), (3, 10.0), (4, 13.0), (5, 17.0), (6, 27.0)] {
        app.inject_packet(udp(no, false, resolver, 10, timestamp));
    }
    app.inject_packet(udp(7, true, resolver, 10, 32.0));
    drain(&mut app);
    let trigger = noise(&mut app, 8, 33.0);
    app.inject_packet(udp(trigger, true, "10.0.0.54", 10, 34.0));
    let expected = [1, 6, 7, trigger];
    let scope = finish_app(&mut app, "dns.competing_responders", &expected);
    let retry = udp(6, false, resolver, 10, 27.0);
    let exchange = app.query_core(|core| core.security.dns_exchange_for_packet(&retry)).unwrap().unwrap();
    assert_eq!(exchange.repeated_query_packets, [2, 3, 4, 5]);
    assert_eq!(exchange.timing_retry.unwrap().packet, 6);

    let mut archive = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(archive.count().unwrap(), expected.len() as u64);
    for frame in expected {
        assert!(archive.packet_for_capture(&scope, frame).unwrap().is_some());
    }
}

fn tcp(no: u64, seq: u32, flags: u8, reply: bool, payload: &[u8], time: f64) -> Packet {
    let mut raw = udp(no, reply, "10.0.0.53", 0, time).bytes;
    raw.resize(54, 0);
    raw[16..18].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    raw[23] = 6;
    raw[38..54].fill(0);
    raw[38..42].copy_from_slice(&seq.to_be_bytes());
    raw[46] = 0x50;
    raw[47] = flags;
    raw.extend_from_slice(payload);
    parse_ethernet(&raw, no, time)
}

fn framed(reply: bool, answer: u8) -> Vec<u8> {
    let mut message = dns_packet(1, reply, "10.0.0.5", "10.0.0.53", 14, "audit.test");
    if reply { append_answer(&mut message, &[0xc0, 0x0c], 1, 60, &[192, 0, 2, answer]); }
    let message = &message.bytes[42..];
    [(message.len() as u16).to_be_bytes().as_slice(), message].concat()
}

#[test]
fn opted_in_tcp_dns_answer_change_archives_segments_of_all_three_messages() {
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("archive");
    let rule = "dns.changed_answers";
    let mut app = start_app(&path, vec![rule.into()]);
    let query = framed(false, 0);
    let response = framed(true, 1);
    let changed = framed(true, 2);
    let seq = 501 + response.len() as u32;
    for packet in [
        tcp(1, 100, 0x02, false, &[], 1.0),
        tcp(2, 500, 0x12, true, &[], 2.0),
        tcp(3, 101, 0x18, false, &query[..5], 3.0),
        tcp(4, 106, 0x18, false, &query[5..], 4.0),
        tcp(5, 501, 0x18, true, &response[..5], 5.0),
        tcp(6, 506, 0x18, true, &response[5..], 6.0),
        tcp(7, seq, 0x18, true, &changed[..5], 7.0),
    ] {
        app.inject_packet(packet);
    }
    drain(&mut app);
    let trigger = noise(&mut app, 8, 8.0);
    app.inject_packet(tcp(trigger, seq + 5, 0x18, true, &changed[5..], 9.0));
    let expected = [3, 4, 5, 6, 7, trigger];
    let scope = finish_app(&mut app, rule, &expected);
    let mut archive = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(archive.count().unwrap(), expected.len() as u64);
    for frame in expected {
        assert!(archive.packet_for_capture(&scope, frame).unwrap().is_some());
    }
}

#[test]
fn delayed_tcp_dns_answer_change_archives_both_segments_of_the_query_retry() {
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("archive");
    let rule = "dns.changed_answers";
    let mut app = start_app(&path, vec![rule.into()]);
    let query = framed(false, 0);
    let response = framed(true, 1);
    let retry_seq = 101 + query.len() as u32;
    for packet in [
        tcp(1, 100, 0x02, false, &[], 1.0),
        tcp(2, 500, 0x12, true, &[], 2.0),
        tcp(3, 101, 0x18, false, &query, 3.0),
        tcp(4, retry_seq, 0x18, false, &query[..5], 27.0),
        tcp(5, retry_seq + 5, 0x18, false, &query[5..], 28.0),
        tcp(6, 501, 0x18, true, &response, 34.0),
        tcp(7, 501 + response.len() as u32, 0x18, true, &framed(true, 2), 35.0),
    ] {
        app.inject_packet(packet);
    }
    let expected = [3, 4, 5, 6, 7];
    let scope = finish_app(&mut app, rule, &expected);
    let mut archive = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(archive.count().unwrap(), expected.len() as u64);
    for frame in expected {
        assert!(archive.packet_for_capture(&scope, frame).unwrap().is_some());
    }
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn opted_in_nxdomain_burst_retains_cited_queries_and_replies_after_rollover(#[case] reordered: bool) {
    let scratch = tempfile::tempdir().unwrap();
    let rule = "dns.nxdomain_distinct_names";
    let (client, resolver) = ("10.0.0.5", "10.0.0.53");
    let packet = |frame, index: u16, reply, time| {
        let (source, destination) = if reply { (resolver, client) } else { (client, resolver) };
        let mut bytes = dns_packet(frame, reply, source, destination, index, &format!("host{index}.audit.test")).bytes;
        if reply { bytes[45] = 0x83; }
        parse_ethernet(&bytes, frame, time)
    };
    for selected in [false, true] {
        let path = scratch.path().join(if selected { "selected" } else { "unselected" });
        let rules = if selected { vec![rule.into()] } else { vec!["dns.changed_answers".into()] };
        let mut app = start_app(&path, rules);
        for index in 0..19 {
            let first = 2 * u64::from(index) + 1;
            let time = 1.0 + f64::from(index) / 5.0;
            app.inject_packet(packet(first, index, false, time));
            app.inject_packet(packet(first + 1, index, true, time + 0.1));
        }
        let reply_time = if reordered { 2.0 } else { 7.0 };
        app.inject_packet(packet(39, 19, false, reply_time - 0.5));
        drain(&mut app);
        let trigger = if selected { noise(&mut app, 40, 6.0) } else { 40 };
        app.inject_packet(packet(trigger, 19, true, reply_time));
        let expected: Vec<_> = (1..=39).chain([trigger]).collect();
        let scope = finish_app(&mut app, rule, &expected);
        let mut archive = PacketArchive::open_readonly(&path).unwrap();
        assert_eq!(archive.count().unwrap(), if selected { 40 } else { 0 });
        if selected {
            for frame in expected {
                assert!(archive.packet_for_capture(&scope, frame).unwrap().is_some(), "frame {frame}");
            }
            if reordered {
                assert!(archive.packet_for_capture(&scope, 38).unwrap().unwrap().timestamp > reply_time);
            }
        }
    }
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn high_entropy_dns_archive_preserves_only_opted_in_cited_query_frames(#[case] use_tcp: bool) {
    let rule = "dns.high_entropy_query_burst";
    let scratch = tempfile::tempdir().unwrap();
    let query = |frame, index| {
        let name = format!("abcdefghijklmnpqrstuvwxyz234567{index}.audit.test");
        dns_packet(frame, false, "10.0.0.5", "10.0.0.53", index, &name).bytes
    };
    for selected in [false, true] {
        let path = scratch.path().join(if selected { "selected" } else { "unselected" });
        let rules = vec![if selected { rule } else { "dns.nxdomain_distinct_names" }.into()];
        let mut app = start_app(&path, rules);
        let mut frame = 1;
        let mut sequence = 101;
        let mut expected = Vec::new();
        if use_tcp {
            app.inject_packet(tcp(frame, 100, 0x02, false, &[], 0.5));
            frame += 1;
        }
        for index in 0..8 {
            if index == 7 {
                frame = noise(&mut app, frame, 8.0);
            }
            let bytes = query(frame, index);
            let time = 1.0 + f64::from(index) * 2.0;
            if use_tcp {
                let message = &bytes[42..];
                let framed = [(message.len() as u16).to_be_bytes().as_slice(), message].concat();
                for (part, bytes) in [&framed[..5], &framed[5..]].into_iter().enumerate() {
                    app.inject_packet(tcp(frame, sequence, 0x18, false, bytes, time + part as f64));
                    expected.push(frame);
                    frame += 1;
                    sequence += bytes.len() as u32;
                }
            } else {
                app.inject_packet(parse_ethernet(&bytes, frame, time));
                expected.push(frame);
                frame += 1;
            }
            drain(&mut app);
        }
        let scope = finish_app(&mut app, rule, &expected);
        let mut archive = PacketArchive::open_readonly(&path).unwrap();
        assert_eq!(archive.count().unwrap(), if selected { expected.len() as u64 } else { 0 });
        for frame in expected {
            assert_eq!(archive.packet_for_capture(&scope, frame).unwrap().is_some(), selected);
        }
    }
}
