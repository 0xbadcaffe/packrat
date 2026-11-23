use super::ipv4_fragment_packet;
use packrat_tui::app::App;
use packrat_tui::engine::worker::WorkerLimits;
use packrat_tui::net::parser::parse_ethernet;
use packrat_tui::storage::packet_archive::{ArchiveLimits, ArchiveWorker, PacketArchive};
use std::path::Path;
use std::time::{Duration, Instant};

fn start(path: &Path, rules: Vec<String>) -> App {
    let mut app = App::new_for_test();
    let archive = ArchiveWorker::open_alert_evidence(path, ArchiveLimits::default()).unwrap();
    app.set_packet_archive_with_rules(archive, rules).unwrap();
    app.start_background_analysis().unwrap();
    app
}

fn drain(app: &mut App) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !app.analysis_idle() {
        app.poll_analysis();
        assert!(Instant::now() < deadline, "analysis did not drain");
        std::thread::yield_now();
    }
}

fn roll_history(app: &mut App, first: u64) -> u64 {
    drain(app);
    let trigger = first + WorkerLimits::default().history_packets as u64 + 1;
    for frame in first..trigger {
        app.inject_packet(parse_ethernet(&[0; 14], frame, 6.0));
        drain(app);
    }
    app.packets.clear();
    trigger
}

fn finish(app: &mut App) {
    drain(app);
    app.stop_background_analysis().unwrap();
    app.packet_archive.as_mut().unwrap().finish().unwrap();
}

#[test]
fn ipv4_overlap_archives_the_exact_older_fragment_under_the_default_selective_policy() {
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("archive");
    let mut app = start(&path, Vec::new());
    let original = ipv4_fragment_packet(1, 7, 0, true, b"abcdefghijklmnop");
    app.inject_packet(original.clone());
    app.inject_packet(ipv4_fragment_packet(2, 7, 0, true, b"abcdefghijklmnop"));
    app.inject_packet(ipv4_fragment_packet(3, 8, 0, true, b"abcdefghijklmnop"));
    let trigger = roll_history(&mut app, 4);
    let mut incoming = ipv4_fragment_packet(trigger, 7, 8, false, b"XXXXXXXX");
    incoming.timestamp = 0.5;
    app.inject_packet(incoming.clone());
    finish(&mut app);

    let alert = app.query_core(|core| core.alert_center.items.iter().find(|alert|
        alert.title == "Conflicting IPv4 fragments").cloned()).unwrap().unwrap();
    assert_eq!(alert.packet_refs, [1, trigger]);
    let scope = alert.capture_id.unwrap();
    let mut archive = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(archive.count().unwrap(), 2);
    for packet in [original, incoming] {
        assert_eq!(archive.packet_for_capture(&scope, packet.no).unwrap().unwrap().bytes, packet.bytes);
    }
}

#[test]
fn opted_in_ipv4_fragment_burst_archives_only_cited_offsets_within_the_event_budget() {
    let rule = "ipv4.fragment_observation_burst";
    for opt_in in [false, true] {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("archive");
        let mut app = start(&path, opt_in.then(|| rule.into()).into_iter().collect());
        let fragment = |frame, id, offset| {
            let mut packet = ipv4_fragment_packet(frame, id, offset, true, b"abcdefgh");
            packet.timestamp = 5.0;
            packet
        };
        for index in 0..64_u16 {
            app.inject_packet(fragment(u64::from(index) + 1, 7, index * 8));
            drain(&mut app);
        }
        app.inject_packet(fragment(65, 7, 0));
        app.inject_packet(fragment(66, 8, 0));
        let trigger = roll_history(&mut app, 67);
        app.inject_packet(fragment(trigger, 7, 64 * 8));
        finish(&mut app);

        let alert = app.query_core(|core| core.alert_center.items.iter().find(|alert|
            alert.provenance.as_ref().is_some_and(|p| p.rule_id == rule)).cloned()).unwrap().unwrap();
        let refs: Vec<_> = (1..=64).chain(std::iter::once(trigger)).collect();
        assert_eq!(alert.packet_refs, refs);
        let scope = alert.capture_id.unwrap();
        let mut archive = PacketArchive::open_readonly(&path).unwrap();
        assert_eq!(archive.count().unwrap(), if opt_in { 32 } else { 0 });
        for frame in refs.into_iter().chain([65, 66]) {
            assert_eq!(archive.packet_for_capture(&scope, frame).unwrap().is_some(),
                opt_in && ((34..=64).contains(&frame) || frame == trigger));
        }
    }
}
