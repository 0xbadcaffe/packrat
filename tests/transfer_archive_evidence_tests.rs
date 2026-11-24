#![cfg(feature = "terminal-ui")]

#[path = "support/packets.rs"]
mod packets;

use packrat_tui::app::App;
use packrat_tui::engine::worker::WorkerLimits;
use packrat_tui::net::{packet::Packet, parser::parse_ethernet};
use packrat_tui::storage::packet_archive::{ArchiveLimits, ArchiveWorker, PacketArchive};
use std::time::{Duration, Instant};

const RULE: &str = "traffic.asymmetric_outbound";
const PAYLOAD: [u8; 1200] = [0; 1200];

fn transfer_frame(no: u64, reverse: bool) -> Packet {
    let mut packet = if reverse {
        packets::tcp(no, 100, 0x18, b"fixture response")
    } else {
        packets::tcp(no, no as u32 * 2000, 0x18, &PAYLOAD)
    };
    packet.bytes[26..34].copy_from_slice(&[10, 0, 0, 5, 198, 51, 100, 10]);
    if reverse {
        for offset in 0..4 {
            packet.bytes.swap(26 + offset, 30 + offset);
        }
        for offset in 0..2 {
            packet.bytes.swap(34 + offset, 36 + offset);
        }
    }
    parse_ethernet(&packet.bytes, no, no as f64 * 0.1)
}

fn inject_and_drain(app: &mut App, packet: Packet) {
    app.inject_packet(packet);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !app.analysis_idle() {
        app.poll_analysis();
        assert!(Instant::now() < deadline, "analysis did not drain");
        std::thread::yield_now();
    }
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn selected_transfer_archive_preserves_both_directions_after_rollover(#[case] selected: bool) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive");
    let mut app = App::new_for_test();
    let archive = ArchiveWorker::open_alert_evidence(&path, ArchiveLimits::default()).unwrap();
    app.set_packet_archive_with_rules(
        archive,
        selected.then(|| RULE.to_owned()).into_iter().collect(),
    )
    .unwrap();
    app.start_background_analysis().unwrap();

    let reverse = transfer_frame(1, true);
    inject_and_drain(&mut app, reverse.clone());
    let outbound_needed = 1_000_000_usize.div_ceil(transfer_frame(2, false).bytes.len()) as u64;
    for frame in 2..=outbound_needed {
        inject_and_drain(&mut app, transfer_frame(frame, false));
    }
    assert!(
        app.query_core(|core| core.alert_center.items.is_empty())
            .unwrap()
    );

    let trigger = outbound_needed + WorkerLimits::default().history_packets as u64 + 2;
    for frame in outbound_needed + 1..trigger {
        inject_and_drain(
            &mut app,
            parse_ethernet(&[0; 14], frame, frame as f64 * 0.1),
        );
    }
    app.packets.clear();
    inject_and_drain(&mut app, transfer_frame(trigger, false));
    app.stop_background_analysis().unwrap();
    app.packet_archive.as_mut().unwrap().finish().unwrap();

    let (scope, citations) = app
        .query_core(move |core| {
            let findings: Vec<_> = core
                .alert_center
                .items
                .iter()
                .filter(|alert| {
                    alert
                        .provenance
                        .as_ref()
                        .is_some_and(|rule| rule.rule_id == RULE)
                })
                .collect();
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, "HIGH");
            (
                findings[0].capture_id.clone().unwrap(),
                findings[0].packet_refs.clone(),
            )
        })
        .unwrap();
    let expected: Vec<_> = [1]
        .into_iter()
        .chain(outbound_needed - 6..=outbound_needed)
        .chain([trigger])
        .collect();
    assert_eq!(citations, expected);

    let mut reader = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(
        reader.count().unwrap(),
        if selected { expected.len() as u64 } else { 1 }
    );
    for frame in expected {
        let original = if frame == 1 {
            reverse.clone()
        } else {
            transfer_frame(frame, false)
        };
        let archived = reader.packet_for_capture(&scope, frame).unwrap();
        assert_eq!(
            archived.map(|packet| packet.bytes),
            (selected || frame == trigger).then_some(original.bytes)
        );
    }
}
