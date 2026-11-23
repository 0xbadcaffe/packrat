#[path = "support/http.rs"]
mod support;

use std::{path::Path, process::Command};

use packrat_tui::export::pcapng::PcapNgWriter;
use serde_json::Value;

fn write_fixture(path: &Path, anchored: bool, gap: bool, overlap: Option<bool>) {
    let request = b"GET /status HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let response = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
    let split = response.len() - 3;
    let mut overlapping_tail = response[split - 1..].to_vec();
    if overlap == Some(true) {
        overlapping_tail[0] = b'X';
    }
    let mut writer = PcapNgWriter::create(path).unwrap();
    let mut frame = 0;
    let mut write = |sequence, flags, payload, reverse| {
        frame += 1;
        writer
            .write_packet(&support::tcp(frame, sequence, flags, payload, reverse))
            .unwrap();
    };
    if anchored {
        write(100, 0x02, &[], false);
        write(500, 0x12, &[], true);
    }
    for index in 0..5 {
        let sequence = 501 + index * response.len() as u32;
        let tail = sequence + split as u32 + u32::from(gap && index == 4);
        write(101 + index * request.len() as u32, 0x18, request, false);
        if index == 4 && overlap.is_some() {
            write(sequence, 0x18, &response[..split], true);
            write(tail - 1, 0x18, &overlapping_tail, true);
        } else if index == 4 && anchored && !gap {
            write(tail, 0x18, &response[split..], true);
            write(sequence, 0x18, &response[..split], true);
        } else {
            write(sequence, 0x18, &response[..split], true);
            write(tail, 0x18, &response[split..], true);
        }
        write(tail, 0x18, &response[split..], true);
    }
    writer.flush().unwrap();
}

#[test]
fn split_401_bursts_use_only_complete_scoped_headers_and_keep_each_frame() {
    let scratch = tempfile::tempdir().unwrap();
    let rule = "http.unauthorized_burst";
    for (name, anchored, gap, overlap, count) in [
        ("split", true, false, None, 1),
        ("gap", true, true, None, 0),
        ("unanchored", false, false, None, 0),
        ("identical-overlap", true, false, Some(false), 1),
        ("conflicting-overlap", true, false, Some(true), 0),
    ] {
        let path = scratch.path().join(format!("{name}.pcapng"));
        write_fixture(&path, anchored, gap, overlap);
        let output = Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
            .args(["--expect-alert", &format!("{rule}={count}")])
            .arg(&path)
            .output()
            .unwrap();
        assert!(output.status.success(), "{name}: {}", String::from_utf8_lossy(&output.stdout));
        let rows: Vec<Value> = String::from_utf8(output.stdout).unwrap().lines()
            .map(|line| serde_json::from_str(line).unwrap()).collect();
        if overlap == Some(true) {
            assert!(rows.iter().any(|row| row["alert"]["provenance"]["rule_id"] == "tcp.conflicting_retransmission"));
            let inspection = Command::new(env!("CARGO_BIN_EXE_packrat-analyze")).arg(&path).output().unwrap();
            assert!(inspection.status.success());
            assert!(String::from_utf8(inspection.stdout).unwrap().lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .filter(|row| row["type"] == "http_conversation")
                .any(|row| row["conversation"]["limitations"].as_array().is_some_and(|notes| {
                    notes.iter().any(|note| note.as_str().is_some_and(|text| text.contains("Conflicting TCP overlap")))
                })));
        }
        let alerts: Vec<_> = rows.iter().filter(|row| row["alert"]["provenance"]["rule_id"] == rule).collect();
        assert_eq!(alerts.len(), count);
        if count == 1 {
            let alert = &alerts[0]["alert"];
            assert_eq!(alerts[0]["opening"], true);
            assert_eq!(alert["packet_no"], 21);
            assert_eq!(alert["provenance"]["revision"], 13);
            assert!(alert["detail"].as_str().unwrap().contains("for 5/5 sampled 401 replies"));
            let mut frames: Vec<_> = alert["packet_refs"].as_array().unwrap().iter()
                .map(|frame| frame.as_u64().unwrap()).collect();
            frames.sort_unstable();
            assert_eq!(frames, (3..22).filter(|frame| (frame + 2) % 4 != 0).collect::<Vec<_>>());
        }
    }
}

#[cfg(feature = "terminal-ui")]
#[test]
fn opted_in_http_burst_archives_all_matched_request_and_response_frames_after_rollover() {
    use packrat_tui::app::App;
    use packrat_tui::engine::worker::WorkerLimits;
    use packrat_tui::net::parser::parse_ethernet;
    use packrat_tui::storage::packet_archive::{ArchiveLimits, ArchiveWorker, PacketArchive};
    use std::time::{Duration, Instant};

    let request = b"GET /status HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let response = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
    let split = response.len() - 3;
    let rule = "http.unauthorized_burst";
    let drain = |app: &mut App| {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !app.analysis_idle() {
            app.poll_analysis();
            assert!(Instant::now() < deadline, "analysis did not drain");
            std::thread::yield_now();
        }
    };
    for selected in [false, true] {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("archive");
        let mut app = App::new_for_test();
        let archive = ArchiveWorker::open_alert_evidence(&path, ArchiveLimits::default()).unwrap();
        app.set_packet_archive_with_rules(archive, selected.then(|| rule.into()).into_iter().collect()).unwrap();
        app.start_background_analysis().unwrap();
        app.inject_packet(support::tcp(1, 100, 0x02, &[], false));
        app.inject_packet(support::tcp(2, 500, 0x12, &[], true));
        for index in 0..5 {
            let frame = 3 + 3 * index;
            let first = 501 + index as u32 * response.len() as u32;
            app.inject_packet(support::tcp(frame, 101 + index as u32 * request.len() as u32, 0x18, request, false));
            app.inject_packet(support::tcp(frame + 1, first, 0x18, &response[..split], true));
            if index < 4 {
                app.inject_packet(support::tcp(frame + 2, first + split as u32, 0x18, &response[split..], true));
            }
        }
        let unrelated = support::tcp(17, 100, 0x18, b"other flow", false);
        let mut bytes = unrelated.bytes;
        bytes[34..36].copy_from_slice(&40_001_u16.to_be_bytes());
        app.inject_packet(parse_ethernet(&bytes, 17, 17.0));
        drain(&mut app);
        let trigger = 19 + WorkerLimits::default().history_packets as u64;
        for no in 18..trigger {
            app.inject_packet(parse_ethernet(&[0; 14], no, 17.0));
            drain(&mut app);
        }
        app.packets.clear();
        let mut final_segment = support::tcp(trigger, 501 + 4 * response.len() as u32 + split as u32, 0x18, &response[split..], true);
        final_segment.timestamp = 18.0;
        app.inject_packet(final_segment);
        drain(&mut app);
        app.stop_background_analysis().unwrap();
        app.packet_archive.as_mut().unwrap().finish().unwrap();

        let alert = app.query_core(|core| core.alert_center.items.iter().find(|alert|
            alert.provenance.as_ref().is_some_and(|p| p.rule_id == rule)).cloned()).unwrap().unwrap();
        assert!(alert.detail.contains("for 5/5 sampled 401 replies"));
        let expected: Vec<_> = (3..=16).chain([trigger]).collect();
        let mut referenced = alert.packet_refs;
        referenced.sort_unstable();
        assert_eq!(referenced, expected);
        let scope = alert.capture_id.unwrap();
        let mut archive = PacketArchive::open_readonly(&path).unwrap();
        assert_eq!(archive.count().unwrap(), if selected { 15 } else { 0 });
        for frame in expected {
            assert_eq!(archive.packet_for_capture(&scope, frame).unwrap().is_some(), selected);
        }
        for frame in [1, 2, 17] {
            assert!(archive.packet_for_capture(&scope, frame).unwrap().is_none());
        }
    }
}
