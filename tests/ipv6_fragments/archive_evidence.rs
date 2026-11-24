use super::{fragment_packet, on_clock};
use packrat_tui::app::App;
use packrat_tui::engine::worker::WorkerLimits;
use packrat_tui::net::parser::parse_ethernet;
use packrat_tui::storage::packet_archive::{ArchiveLimits, ArchiveWorker, PacketArchive};
use std::time::{Duration, Instant};

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

#[test]
fn overlap_archive_recovers_the_cited_fragment_after_rollover_without_other_frames() {
    for (conflict, opt_in) in [(true, false), (false, false), (false, true)] {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("archive");
        let mut app = App::new_for_test();
        let rule = if conflict { "ipv6.conflicting_fragments" } else { "ipv6.reassembly_rejected" };
        let archive = ArchiveWorker::open_alert_evidence(&path, ArchiveLimits::default()).unwrap();
        app.set_packet_archive_with_rules(archive, opt_in.then(|| rule.into()).into_iter().collect()).unwrap();
        app.start_background_analysis().unwrap();
        let original = fragment_packet(1, 7, 0, true, b"abcdefghijklmnop");
        app.inject_packet(original.clone());
        app.inject_packet(fragment_packet(2, 7, 0, true, b"abcdefghijklmnop"));
        app.inject_packet(fragment_packet(3, 8, 0, true, b"abcdefghijklmnop"));
        app.inject_packet(on_clock(fragment_packet(4, 19, 0, true, b"ordinary"), 400, (0, 1)));
        let trigger = roll_history(&mut app, 5);
        let payload = if conflict { b"XXXXXXXXqrstuvwx" } else { b"ijklmnopqrstuvwx" };
        let mut incoming = fragment_packet(trigger, 7, 8, true, payload);
        incoming.timestamp = 0.5;
        app.inject_packet(incoming.clone());
        drain(&mut app);
        app.stop_background_analysis().unwrap();
        app.packet_archive.as_mut().unwrap().finish().unwrap();

        let alert = app.query_core(|core| core.alert_center.items.iter().find(|alert|
            alert.provenance.as_ref().is_some_and(|p| p.rule_id == rule)).cloned()).unwrap().unwrap();
        assert_eq!(alert.packet_refs, [1, trigger]);
        assert_eq!(alert.provenance.as_ref().unwrap().revision, if conflict { 4 } else { 3 });
        let scope = alert.capture_id.unwrap();
        let mut archive = PacketArchive::open_readonly(&path).unwrap();
        let expected = conflict || opt_in;
        assert_eq!(archive.count().unwrap(), if expected { 2 } else { 0 });
        for packet in [original, incoming] {
            assert_eq!(archive.packet_for_capture(&scope, packet.no).unwrap().map(|saved| saved.bytes),
                expected.then_some(packet.bytes));
        }
    }
}

#[test]
fn investigation_reopens_opted_in_reassembled_alert_with_original_frames() {
    let rule = "payload.script_like_marker";
    for opt_in in [false, true] {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("archive");
        let mut app = App::new_for_test();
        let archive = ArchiveWorker::open_alert_evidence(&path, ArchiveLimits::default()).unwrap();
        app.set_packet_archive_with_rules(archive, opt_in.then(|| rule.into()).into_iter().collect()).unwrap();
        app.start_background_analysis().unwrap();
        let tail = fragment_packet(1, 7, 24, false, b"ript>");
        app.inject_packet(tail.clone());
        app.inject_packet(fragment_packet(2, 7, 24, false, b"ript>"));
        app.inject_packet(fragment_packet(3, 8, 24, false, b"text."));
        app.inject_packet(on_clock(fragment_packet(4, 19, 0, true, b"ordinary"), 400, (0, 1)));
        let trigger = roll_history(&mut app, 5);
        let mut head = fragment_packet(trigger, 7, 0, true, b"abcdefghijklmnopqrstu<sc");
        head.timestamp = 6.0;
        app.inject_packet(head.clone());
        drain(&mut app);
        app.stop_background_analysis().unwrap();
        app.packet_archive.as_mut().unwrap().finish().unwrap();
        app.packets.clear();

        let alert = app.query_core(|core| core.alert_center.items.iter().find(|alert|
            alert.provenance.as_ref().is_some_and(|p| p.rule_id == rule)).cloned()).unwrap().unwrap();
        assert_eq!(alert.packet_refs, [1, trigger]);
        assert_eq!(alert.provenance.as_ref().unwrap().revision, 3);
        assert!(app.investigate_selected_alert());
        if opt_in {
            assert_eq!(app.worklist.packet_nos(), [1, trigger]);
            assert_eq!(app.active_investigation_packet().unwrap().bytes, head.bytes);
        } else {
            assert!(app.worklist.packet_nos().is_empty());
        }
        let scope = alert.capture_id.unwrap();
        let mut archive = PacketArchive::open_readonly(&path).unwrap();
        assert_eq!(archive.count().unwrap(), if opt_in { 2 } else { 0 });
        for packet in [tail, head] {
            assert_eq!(archive.packet_for_capture(&scope, packet.no).unwrap().map(|saved| saved.bytes),
                opt_in.then_some(packet.bytes));
        }
    }
}

#[test]
fn final_length_rejection_recovers_the_cited_boundary_after_rollover() {
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("archive");
    let mut app = App::new_for_test();
    let archive = ArchiveWorker::open_alert_evidence(&path, ArchiveLimits::default()).unwrap();
    app.set_packet_archive_with_rules(archive, Vec::new()).unwrap();
    app.start_background_analysis().unwrap();
    let boundary = fragment_packet(1, 7, 8, false, b"ijklmnop");
    app.inject_packet(boundary.clone());
    app.inject_packet(fragment_packet(2, 7, 8, false, b"ijklmnop"));
    app.inject_packet(fragment_packet(3, 8, 8, false, b"ijklmnop"));
    let trigger = roll_history(&mut app, 4);
    let mut incoming = fragment_packet(trigger, 7, 16, true, b"qrstuvwx");
    incoming.timestamp = 0.5;
    app.inject_packet(incoming.clone());
    drain(&mut app);
    app.stop_background_analysis().unwrap();
    app.packet_archive.as_mut().unwrap().finish().unwrap();

    let alert = app.query_core(|core| core.alert_center.items.iter().find(|alert|
        alert.provenance.as_ref().is_some_and(|p| p.rule_id == "ipv6.reassembly_rejected")).cloned()).unwrap().unwrap();
    assert_eq!(alert.packet_refs, [1, trigger]);
    let scope = alert.capture_id.unwrap();
    let mut archive = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(archive.count().unwrap(), 2);
    for packet in [boundary, incoming] {
        assert_eq!(archive.packet_for_capture(&scope, packet.no).unwrap().unwrap().bytes, packet.bytes);
    }
}
