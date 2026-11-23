use super::*;
use crate::engine::PacketAnalysis;

fn router_advertisement_fixture(frame: u64, host: u8, vlan: u16) -> Packet {
    use crate::net::packet::{CaptureMetadata, CaptureTimestamp, TimestampResolution};

    let mut bytes = vec![0x33, 0x33, 0, 0, 0, 1, 2, 0, 0, 0, 0, host, 0x81, 0];
    bytes.extend(vlan.to_be_bytes());
    bytes.extend([0x86, 0xdd, 0x60, 0, 0, 0, 0, 16, 58, 255]);
    for address in ["fe80::1", "ff02::1"] {
        bytes.extend(address.parse::<std::net::Ipv6Addr>().unwrap().octets());
    }
    bytes.extend([134, 0, 0x7b, 0xf3, 0, 0, 0, 60, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut packet = crate::net::parser::parse_ethernet(&bytes, frame, frame as f64);
    let length = bytes.len() as u32;
    packet.capture = Some(CaptureMetadata {
        timestamp: Some(CaptureTimestamp { ticks: frame, resolution: TimestampResolution::Decimal(0), offset_seconds: 0 }),
        captured_length: length, wire_length: length, link_type: 1, section_id: 0, interface_id: 0,
        interface_name: None, comments: Vec::new(),
    });
    packet
}

#[test]
fn detected_router_change_is_saved_and_only_opted_in_evidence_is_archived() {
    use crate::storage::{
        alert_evidence::{FrameStatus, alert_evidence_availability, export_scoped_alert_evidence,
            verify_archived_alert_evidence},
        alert_history::AlertLogs,
        alert_jsonl::AlertJsonlWriter,
        packet_archive::{ArchiveLimits, ArchiveWorker, PacketArchive},
    };

    let rule = "ipv6.ra_router_link_change";
    for selected in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let archive_path = directory.path().join("archive");
        let log = directory.path().join("alerts.jsonl");
        let mut app = App::new_for_test();
        let archive = ArchiveWorker::open_alert_evidence(&archive_path, ArchiveLimits::default()).unwrap();
        let rules = selected.then(|| rule.to_owned()).into_iter().collect();
        app.set_packet_archive_with_rules(archive, rules).unwrap();
        let scope = app.capture_id.clone().unwrap();
        let session = app.alert_session_id.clone();
        let writer = AlertJsonlWriter::open(log.clone(), &session).unwrap();
        app.configure_core(move |core| {
            core.alert_jsonl_writer = Some(std::sync::Arc::new(std::sync::Mutex::new(writer)));
        });
        app.start_background_analysis().unwrap();
        for (frame, host, vlan) in [(1, 1, 10), (2, 2, 20), (3, 3, 10)] {
            app.inject_packet(router_advertisement_fixture(frame, host, vlan));
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !app.analysis_idle() {
            app.poll_analysis();
            assert!(std::time::Instant::now() < deadline, "background analysis did not finish");
            std::thread::yield_now();
        }
        app.stop_background_analysis().unwrap();
        app.packet_archive.as_mut().unwrap().finish().unwrap();

        let rows: Vec<serde_json::Value> = std::fs::read_to_string(&log).unwrap().lines()
            .map(|row| serde_json::from_str(row).unwrap()).collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["alert"]["provenance"]["rule_id"], rule);
        assert_eq!(rows[0]["alert"]["packet_refs"], serde_json::json!([1, 3]));
        let id = rows[0]["alert"]["id"].as_u64().unwrap();
        let mut reader = PacketArchive::open_readonly(&archive_path).unwrap();
        assert_eq!(reader.count().unwrap(), if selected { 2 } else { 0 });
        assert!(reader.packet_for_capture(&scope, 2).unwrap().is_none());
        let status = alert_evidence_availability(&mut reader, &log, &session, id, Some(&scope)).unwrap();
        assert_eq!(status.frames.iter().map(|frame| frame.frame_number).collect::<Vec<_>>(), [1, 3]);
        assert!(status.frames.iter().all(|frame| frame.status == if selected { FrameStatus::Complete } else { FrameStatus::Missing }));
        if selected {
            let bundle = directory.path().join("evidence");
            export_scoped_alert_evidence(&mut reader, &log, &session, id, Some(&scope), &bundle).unwrap();
            let report = verify_archived_alert_evidence(&bundle, &archive_path, Some(AlertLogs::new(&log, &[]).unwrap())).unwrap();
            assert_eq!(report.archive_frames_verified, Some(2));
            assert_eq!(report.alert_snapshot_matches_log, Some(true));
        }
    }
}

#[test]
fn selective_archive_retains_scoped_high_alert_frames_without_pinning_unrelated_traffic() {
    use crate::storage::packet_archive::{ArchiveLimits, ArchiveWorker, PacketArchive};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("archive");
    let mut app = App::new_for_test();
    app.set_packet_archive(ArchiveWorker::open_alert_evidence(&path, ArchiveLimits::default()).unwrap()).unwrap();
    let scope = app.capture_id.clone().unwrap();
    for frame in 1..=4 {
        app.inject_packet(packet(frame));
    }
    for (trigger, severity, key) in [(2, "HIGH", "first"), (3, "MEDIUM", "ignored"), (4, "CRITICAL", "second")] {
        let analysis = {
            let mut core = app.core.edit();
            core.alert_center.automation_mode = AutomationMode::Off;
            core.alert_center.record_correlated_with_evidence(
                (trigger, &[1]), trigger as f64, "TEST", severity, key, "observation", key,
            );
            PacketAnalysis { alert_pins: core.alert_center.drain_pending_pins(), ..Default::default() }
        };
        let context = app.analysis_context(&analysis).unwrap();
        app.handle_packet_analysis(analysis, context, false, false, &[]);
    }
    assert!(app.worklist.items.is_empty());
    app.packet_archive.as_mut().unwrap().finish().unwrap();
    let mut reader = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(reader.count().unwrap(), 3);
    assert!(reader.packet_for_capture(&scope, 3).unwrap().is_none());
    for n in [1, 2, 4] {
        assert_eq!(reader.packet_for_capture(&scope, n).unwrap().unwrap().no, n);
    }
}

#[test]
fn background_alert_archives_supporting_bytes_after_display_eviction() {
    use crate::storage::packet_archive::{ArchiveLimits, ArchiveWorker, PacketArchive};
    use std::time::{Duration, Instant};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("archive");
    let mut app = App::new_for_test();
    app.set_packet_archive(ArchiveWorker::open_alert_evidence(&path, ArchiveLimits::default()).unwrap()).unwrap();
    let scope = app.capture_id.clone().unwrap();
    app.start_background_analysis().unwrap();
    let wait = |app: &mut App| {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !app.analysis_idle() {
            app.poll_analysis();
            assert!(Instant::now() < deadline, "background analysis did not finish");
            std::thread::yield_now();
        }
    };
    app.inject_packet(packet(1));
    wait(&mut app);
    assert_eq!(app.packets.front().unwrap().no, 1);
    app.packets.clear();
    app.configure_core(|core| {
        core.alert_center.automation_mode = AutomationMode::Off;
        core.alert_center.record_correlated_with_evidence(
            (2, &[1]), 2.0, "TEST", "HIGH", "Finding", "observed", "flow",
        );
    });
    app.inject_packet(packet(2));
    wait(&mut app);
    assert!(app.packet_by_no(1).is_none());
    app.stop_background_analysis().unwrap();
    app.packet_archive.as_mut().unwrap().finish().unwrap();
    let mut reader = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(reader.count().unwrap(), 2);
    assert_eq!(reader.packet_for_capture(&scope, 1).unwrap().unwrap().bytes, packet(1).bytes);
}

#[test]
fn selective_archive_retains_only_named_medium_rules_and_their_updates() {
    use crate::storage::packet_archive::{ArchiveLimits, ArchiveWorker, PacketArchive};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("archive");
    let mut app = App::new_for_test();
    let archive = ArchiveWorker::open_alert_evidence(&path, ArchiveLimits::default()).unwrap();
    app.set_packet_archive_with_rules(archive, vec!["tcp.payload_after_observed_reset".into()])
        .unwrap();
    let scope = app.capture_id.clone().unwrap();
    for frame in 1..=4 {
        app.inject_packet(packet(frame));
    }
    for (trigger, title) in [
        (2, "TCP payload after reset"),
        (3, "Periodic fixed-size traffic"),
        (4, "TCP payload after reset"),
    ] {
        let analysis = {
            let mut core = app.core.edit();
            core.alert_center.automation_mode = AutomationMode::Watch;
            core.alert_center.record_correlated_with_evidence(
                (trigger, &[1]), trigger as f64, "IDS", "MEDIUM", title, "observation", title,
            );
            PacketAnalysis {
                alert_pins: core.alert_center.drain_pending_pins(),
                ..Default::default()
            }
        };
        let context = app.analysis_context(&analysis).unwrap();
        app.handle_packet_analysis(analysis, context, false, false, &[]);
    }
    assert!(app.worklist.items.is_empty());
    app.packet_archive.as_mut().unwrap().finish().unwrap();
    let mut reader = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(reader.count().unwrap(), 3);
    assert!(reader.packet_for_capture(&scope, 3).unwrap().is_none());
    for frame in [1, 2, 4] {
        assert!(reader.packet_for_capture(&scope, frame).unwrap().is_some());
    }
}

#[test]
fn watch_preserves_trigger_and_prior_evidence_without_stealing_selection() {
    let mut app = App::new_for_test();
    app.packets.push_back(packet(10));
    app.worklist.pin_packet(&packet(9)).unwrap();
    let trigger = packet(20);
    let pins = {
        let mut core = app.core.edit();
        core.alert_center.automation_mode = AutomationMode::Watch;
        core.alert_center.record_correlated_with_evidence(
            (20, &[10, 11]),
            2.0,
            "IDS",
            "HIGH",
            "Finding",
            "observation",
            "flow-a",
        );
        core.alert_center.drain_pending_pins()
    };
    let analysis = PacketAnalysis {
        alert_pins: pins,
        ..Default::default()
    };
    let context = app.analysis_context(&analysis).unwrap();
    app.handle_packet_analysis(analysis, context, false, false, std::slice::from_ref(&trigger));
    app.packets.clear();

    assert_eq!(app.worklist.active_packet_no(), Some(9));
    assert!(app.worklist.items.contains(&InvestigationItem::Alert(1)));
    assert!(app.worklist.retained_packet(10).is_some());
    assert!(app.worklist.retained_packet(11).is_none());
    assert_eq!(
        app.worklist.retained_packet(20).unwrap().bytes,
        trigger.bytes
    );
    assert!(app.project_dirty);
    assert!(!app.worklist.open);

    let follow_up = packet(30);
    let pins = {
        let mut core = app.core.edit();
        core.alert_center.record_correlated(
            30,
            3.0,
            "IDS",
            "HIGH",
            "Finding",
            "follow-up observation",
            "flow-a",
        );
        core.alert_center.drain_pending_pins()
    };
    let update = PacketAnalysis {
        alert_pins: pins,
        ..Default::default()
    };
    let context = app.analysis_context(&update).unwrap();
    app.handle_packet_analysis(update, context, false, false, std::slice::from_ref(&follow_up));
    assert_eq!(app.worklist.active_packet_no(), Some(9));
    assert_eq!(
        app.worklist.retained_packet(30).unwrap().bytes,
        follow_up.bytes
    );
    assert!(app.worklist.retained_packet(20).is_some());
}

#[test]
fn watch_does_not_retain_packets_from_an_unverified_capture() {
    let mut app = App::new_for_test();
    app.capture_id = Some(App::new_capture_id());
    let pins = {
        let mut core = app.core.edit();
        core.alert_center.automation_mode = AutomationMode::Watch;
        core.alert_center
            .record(20, "IDS", "HIGH", "Unscoped finding", "observation");
        core.alert_center.drain_pending_pins()
    };
    let analysis = PacketAnalysis {
        alert_pins: pins,
        ..Default::default()
    };
    let context = app.analysis_context(&analysis).unwrap();
    app.handle_packet_analysis(analysis, context, false, false, &[packet(20)]);
    assert!(app.worklist.items.is_empty());
    assert!(!app.project_dirty);
}
