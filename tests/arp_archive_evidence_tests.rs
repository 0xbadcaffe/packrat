#![cfg(feature = "terminal-ui")]

#[path = "support/arp.rs"]
mod fixture;

use packrat_tui::app::App;
use packrat_tui::engine::worker::WorkerLimits;
use packrat_tui::net::{packet::Packet, parser::parse_ethernet};
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

fn announcement() -> Packet {
    let mut packet = fixture::reply(1, 1.0, 10, 1);
    packet.bytes[..6].fill(255);
    packet.bytes[25] = 1;
    packet.bytes[36..42].fill(0);
    packet.bytes.copy_within(32..36, 42);
    packet
}

#[rstest::rstest]
#[case(None, &[])]
#[case(Some("arp.announcement_binding_change"), &[0, 1])]
#[case(Some("arp.reply_binding_change"), &[1, 2])]
#[case(Some("arp.alternating_claims"), &[0, 1, 2])]
fn selective_arp_archive_preserves_exact_claims_after_rollover(
    #[case] rule: Option<&str>,
    #[case] saved: &[usize],
) {
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("archive");
    let mut app = App::new_for_test();
    let archive = ArchiveWorker::open_alert_evidence(&path, ArchiveLimits::default()).unwrap();
    app.set_packet_archive_with_rules(archive, rule.into_iter().map(str::to_owned).collect()).unwrap();
    app.start_background_analysis().unwrap();

    let first = announcement();
    app.inject_packet(first.clone());
    app.inject_packet(fixture::reply(2, 2.0, 20, 2));
    let second = fixture::reply(roll_history(&mut app, 3, 2.0), 3.0, 10, 2);
    app.inject_packet(second.clone());
    let third = fixture::reply(roll_history(&mut app, second.no + 1, 3.0), 4.0, 10, 1);
    app.inject_packet(third.clone());
    drain(&mut app);
    app.stop_background_analysis().unwrap();
    app.packet_archive.as_mut().unwrap().finish().unwrap();

    let ids = [first.no, second.no, third.no];
    let (scope, citations) = app.query_core(move |core| {
        let findings: Vec<_> = core.alert_center.items.iter()
            .filter(|alert| alert.provenance.as_ref().is_some_and(|p| p.rule_id.starts_with("arp.")))
            .collect();
        assert_eq!(findings.len(), 3);
        let scope = findings[0].capture_id.clone().unwrap();
        let mut citations: Vec<_> = findings.iter().map(|alert| alert.packet_refs.clone()).collect();
        citations.sort();
        (scope, citations)
    }).unwrap();
    assert_eq!(citations, [ids[..2].to_vec(), ids.to_vec(), ids[1..].to_vec()]);

    let mut archive = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(archive.count().unwrap(), saved.len() as u64);
    for (index, claim) in [first, second, third].into_iter().enumerate() {
        let archived = archive.packet_for_capture(&scope, claim.no).unwrap();
        assert_eq!(archived.map(|packet| packet.bytes), saved.contains(&index).then_some(claim.bytes));
    }
    assert!(archive.packet_for_capture(&scope, 2).unwrap().is_none());
}
