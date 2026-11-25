use super::archive_fixture::{finish, roll_history, start};
use super::cases_2::{HTTP_SPLIT_FIRST, HTTP_SPLIT_LAST};
use super::http_packet;
use packrat_tui::net::packet::{CaptureMetadata, CaptureTimestamp, Packet, TimestampResolution};
use packrat_tui::storage::{alert_evidence::alert_flow_summary, alert_history::AlertLogs};
use packrat_tui::storage::packet_archive::PacketArchive;

fn captured(mut packet: Packet) -> Packet {
    let length = packet.bytes.len() as u32;
    packet.capture = Some(CaptureMetadata {
        timestamp: Some(CaptureTimestamp {
            ticks: packet.timestamp as u64, resolution: TimestampResolution::Decimal(0), offset_seconds: 0,
        }),
        captured_length: length, wire_length: length,
        link_type: 1, section_id: 0, interface_id: 0, interface_name: None, comments: Vec::new(),
    });
    packet
}

#[test]
fn split_http_finding_archives_only_cited_frames_after_worker_history_rollover() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive");
    let mut app = start(&path, Vec::new());
    let first = captured(http_packet(1, 100, HTTP_SPLIT_FIRST));
    app.inject_packet(first.clone());
    app.inject_packet(captured(http_packet(2, 100, HTTP_SPLIT_FIRST)));

    let trigger = roll_history(&mut app, 3);
    let mut last = http_packet(trigger, 100 + HTTP_SPLIT_FIRST.len() as u32, HTTP_SPLIT_LAST);
    last.timestamp = 7.0;
    let last = captured(last);
    app.inject_packet(last.clone());
    finish(&mut app);

    let alert = app.query_core(|core| core.alert_center.items.iter().find(|alert|
        alert.title == "HTTP request smuggling ambiguity").cloned()).unwrap().unwrap();
    assert_eq!(alert.packet_refs, [1, trigger]);
    let scope = alert.capture_id.as_deref().unwrap();
    let mut archive = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(archive.count().unwrap(), 2);
    assert!(archive.packet_for_capture(scope, 2).unwrap().is_none());
    for packet in [first, last] {
        assert_eq!(archive.packet_for_capture(scope, packet.no).unwrap().unwrap().bytes, packet.bytes);
    }
    let log = root.path().join("alerts.jsonl");
    std::fs::write(&log, serde_json::json!({
        "schema_version": 1, "record_type": "alert", "session_id": "test", "alert": alert,
    }).to_string()).unwrap();
    let summary = serde_json::to_value(alert_flow_summary(
        &mut archive, AlertLogs::new(&log, &[]).unwrap(), "test", scope, alert.id,
    ).unwrap()).unwrap();
    assert_eq!(summary["trigger_tuple_status"], "matches_wire");
    assert_eq!(summary["trigger_frame"]["frame_number"], trigger);
    assert_eq!(summary["referenced_frames"], 2);
}
