#![cfg(feature = "terminal-ui")]

#[path = "support/dhcp.rs"]
mod fixture;

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

fn roll_history(app: &mut App, first: u64, time: f64) -> u64 {
    drain(app);
    let trigger = first + WorkerLimits::default().history_packets as u64 + 1;
    for frame in first..trigger {
        app.inject_packet(parse_ethernet(&[0; 14], frame, time));
        drain(app);
    }
    app.packets.clear();
    trigger
}

#[test]
fn opted_in_dhcp_server_change_archives_only_its_own_relay_comparison_after_rollover() {
    let rule = "dhcp.new_server_identifier";
    let reply = |frame, server, relay, time| {
        let packet = fixture::dhcp_packet(
            frame, 2, [2, 0, 0, 0, 0, server], [2; 6], Some([10, 0, 0, server]),
        );
        let mut packet = fixture::relayed_packet(packet, [192, 0, 2, relay]);
        packet.timestamp = time;
        packet
    };
    for selected in [false, true] {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("archive");
        let mut app = App::new_for_test();
        let archive = ArchiveWorker::open_alert_evidence(&path, ArchiveLimits::default()).unwrap();
        app.set_packet_archive_with_rules(archive, selected.then(|| rule.into()).into_iter().collect()).unwrap();
        app.start_background_analysis().unwrap();
        app.inject_packet(reply(1, 1, 1, 1.0));
        app.inject_packet(reply(2, 2, 2, 2.0));
        let comparison = reply(3, 1, 1, 3.0);
        app.inject_packet(comparison.clone());
        let trigger = roll_history(&mut app, 4, 4.0);
        app.inject_packet(reply(trigger, 3, 1, 3602.0));
        drain(&mut app);
        app.stop_background_analysis().unwrap();
        app.packet_archive.as_mut().unwrap().finish().unwrap();

        let alert = app.query_core(|core| core.alert_center.items.iter().find(|alert|
            alert.provenance.as_ref().is_some_and(|p| p.rule_id == rule)).cloned()).unwrap().unwrap();
        assert_eq!(alert.packet_refs, [3, trigger]);
        let scope = alert.capture_id.unwrap();
        let mut archive = PacketArchive::open_readonly(&path).unwrap();
        assert_eq!(archive.count().unwrap(), if selected { 2 } else { 0 });
        assert_eq!(archive.packet_for_capture(&scope, 3).unwrap().map(|packet| packet.bytes), selected.then_some(comparison.bytes));
        assert_eq!(archive.packet_for_capture(&scope, trigger).unwrap().is_some(), selected);
        for unrelated in [1, 2] {
            assert!(archive.packet_for_capture(&scope, unrelated).unwrap().is_none());
        }
    }
}

#[test]
fn opted_in_dhcp_client_burst_keeps_only_sampled_frames_for_a_reordered_trigger() {
    let rule = "dhcp.discover_identity_burst";
    let discovery = |frame, identity, relay, time| {
        let address = [2, 0, 0, 0, 0, identity];
        let mut packet = fixture::relayed_packet(
            fixture::dhcp_packet(frame, 1, address, address, None), [192, 0, 2, relay],
        );
        packet.timestamp = time;
        packet
    };
    for selected in [false, true] {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("archive");
        let mut app = App::new_for_test();
        let archive = ArchiveWorker::open_alert_evidence(&path, ArchiveLimits::default()).unwrap();
        app.set_packet_archive_with_rules(archive, selected.then(|| rule.into()).into_iter().collect()).unwrap();
        app.start_background_analysis().unwrap();
        for identity in 0..63_u8 {
            app.inject_packet(discovery(u64::from(identity) + 1, identity, 1, 5.0));
            drain(&mut app);
        }
        app.inject_packet(discovery(64, 0, 1, 5.0));
        app.inject_packet(discovery(65, 63, 2, 5.0));
        let trigger = roll_history(&mut app, 66, 5.0);
        app.inject_packet(discovery(trigger, 63, 1, 4.0));
        drain(&mut app);
        app.stop_background_analysis().unwrap();
        app.packet_archive.as_mut().unwrap().finish().unwrap();

        let alert = app.query_core(|core| core.alert_center.items.iter().find(|alert|
            alert.provenance.as_ref().is_some_and(|p| p.rule_id == rule)).cloned()).unwrap().unwrap();
        let sampled: Vec<_> = (1..=63).chain(std::iter::once(trigger)).collect();
        assert_eq!(alert.packet_refs, sampled);
        let scope = alert.capture_id.unwrap();
        let mut archive = PacketArchive::open_readonly(&path).unwrap();
        // The worker archives at most 32 frames per event, including the trigger.
        assert_eq!(archive.count().unwrap(), if selected { 32 } else { 0 });
        for frame in sampled {
            assert_eq!(archive.packet_for_capture(&scope, frame).unwrap().is_some(), selected && (frame <= 31 || frame == trigger));
        }
        for frame in [64, 65] {
            assert!(archive.packet_for_capture(&scope, frame).unwrap().is_none());
        }
    }
}
