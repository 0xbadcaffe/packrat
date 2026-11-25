use super::archive_fixture::{finish, roll_history, start};
use super::cases_2::{HTTP_SPLIT_FIRST, HTTP_SPLIT_LAST};
use super::http_packet;
use packrat_tui::storage::packet_archive::PacketArchive;

#[test]
fn split_http_finding_archives_only_cited_frames_after_worker_history_rollover() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive");
    let mut app = start(&path, Vec::new());
    let first = http_packet(1, 100, HTTP_SPLIT_FIRST);
    app.inject_packet(first.clone());
    app.inject_packet(http_packet(2, 100, HTTP_SPLIT_FIRST));

    let trigger = roll_history(&mut app, 3);
    let mut last = http_packet(trigger, 100 + HTTP_SPLIT_FIRST.len() as u32, HTTP_SPLIT_LAST);
    last.timestamp = 7.0;
    app.inject_packet(last.clone());
    finish(&mut app);

    let alert = app.query_core(|core| core.alert_center.items.iter().find(|alert|
        alert.title == "HTTP request smuggling ambiguity").cloned()).unwrap().unwrap();
    assert_eq!(alert.packet_refs, [1, trigger]);
    let scope = alert.capture_id.unwrap();
    let mut archive = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(archive.count().unwrap(), 2);
    assert!(archive.packet_for_capture(&scope, 2).unwrap().is_none());
    for packet in [first, last] {
        assert_eq!(archive.packet_for_capture(&scope, packet.no).unwrap().unwrap().bytes, packet.bytes);
    }
}
