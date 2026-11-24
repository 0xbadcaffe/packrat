use std::{io::Write, path::Path, process::Command};

use packrat_tui::analysis::alert_center::{AlertCenter, AlertFlow, AlertTransport};
use serde_json::{Value, json};

#[path = "support/packets.rs"]
mod packets;

const SCOPE: &[&str] = &["--session", "session-a", "--capture-id", "capture-a"];

fn record(id: u64, time: f64, flow: Option<AlertFlow>, session: &str, capture: &str) -> Value {
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "MEDIUM", "Private title", "Private detail");
    let mut alert = center.items.remove(0);
    alert.id = id;
    alert.capture_id = Some(capture.into());
    alert.first_seen = time;
    alert.last_seen = time;
    alert.flow = flow;
    json!({"schema_version": 1, "record_type": "alert", "session_id": session, "alert": alert})
}

fn flow() -> AlertFlow {
    AlertFlow {
        transport: AlertTransport::Tcp,
        source: "192.0.2.10:40001".parse().unwrap(),
        destination: "198.51.100.20:443".parse().unwrap(),
    }
}

fn command(log: &Path, id: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_packrat-archive"));
    command.arg("--alerts").arg(log).args(["--related-to", id]);
    command
}

fn run(log: &Path, id: &str, extra: &[&str]) -> Value {
    let output = command(log, id).args(SCOPE).args(extra).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Private"));
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn relates_only_nearby_exact_tuples_in_the_same_session_and_capture() {
    let forward = flow();
    let reverse = AlertFlow {
        source: forward.destination,
        destination: forward.source,
        ..forward
    };
    let different_port = AlertFlow {
        source: "192.0.2.10:40002".parse().unwrap(),
        ..forward
    };
    let udp = AlertFlow {
        transport: AlertTransport::Udp,
        ..forward
    };
    let directory = tempfile::tempdir().unwrap();
    let previous = directory.path().join("previous.jsonl");
    let active = directory.path().join("alerts.jsonl");
    let mut prior = std::fs::File::create(&previous).unwrap();
    for (id, time, tuple) in [(2, 1000., forward), (3, 1010., forward), (4, 700., reverse)] {
        writeln!(
            prior,
            "{}",
            record(id, time, Some(tuple), "session-a", "capture-a")
        )
        .unwrap();
    }
    let mut current = std::fs::File::create(&active).unwrap();
    for (id, time, tuple, session, capture) in [
        (3, 1010., reverse, "session-a", "capture-a"),
        (5, 1010., forward, "session-a", "capture-a"),
        (6, 699., forward, "session-a", "capture-a"),
        (7, 999., different_port, "session-a", "capture-a"),
        (8, 1000., udp, "session-a", "capture-a"),
        (2, 1000., udp, "session-b", "capture-a"),
        (9, 1000., forward, "session-a", "capture-b"),
    ] {
        writeln!(
            current,
            "{}",
            record(id, time, Some(tuple), session, capture)
        )
        .unwrap();
    }

    let report = run(
        &active,
        "2",
        &["--previous-log", previous.to_str().unwrap()],
    );
    assert_eq!(report["status"], "sampled");
    assert_eq!(report["scan_complete"], true);
    assert_eq!(report["matching_alerts_in_sample"], 3);
    let matches = report["matches"].as_array().unwrap();
    assert_eq!(matches[0]["alert_id"], 3);
    assert_eq!(matches[0]["direction"], "reverse");
    assert_eq!(matches[1]["alert_id"], 5);
    assert_eq!(matches[1]["direction"], "same");
    assert_eq!(matches[2]["seconds_from_anchor_trigger"], -300.);
}

#[test]
fn times_the_stored_tuple_at_the_latest_hit_and_ignores_missing_times() {
    let mut log = tempfile::NamedTempFile::new().unwrap();
    for (id, first, last) in [
        (1, 500., 900.),
        (2, 100., 910.),
        (3, 530., 1210.),
        (4, 899., 0.),
    ] {
        let mut entry = record(id, first, Some(flow()), "session-a", "capture-a");
        entry["alert"]["hit_count"] = json!(2);
        entry["alert"]["last_seen"] = json!(last);
        writeln!(log, "{entry}").unwrap();
    }
    let report = run(log.path(), "1", &[]);
    assert_eq!(report["anchor_trigger_time"], 900.);
    assert_eq!(report["matching_alerts_in_sample"], 1);
    assert_eq!(report["matches"][0]["alert_id"], 2);
    assert_eq!(report["matches"][0]["seconds_from_anchor_trigger"], 10.);
    let missing = run(log.path(), "4", &[]);
    assert_eq!(missing["status"], "anchor_tuple_or_time_unavailable");
    assert!(missing["anchor_trigger_time"].is_null());
}

#[test]
fn reports_missing_scope_or_tuple_without_implying_no_related_alerts() {
    let mut log = tempfile::NamedTempFile::new().unwrap();
    writeln!(log, "{}", record(1, 100., None, "session-a", "capture-a")).unwrap();
    writeln!(log, "not json").unwrap();
    assert_eq!(run(log.path(), "2", &[])["status"], "anchor_not_in_sample");
    let report = run(log.path(), "1", &[]);
    assert_eq!(report["status"], "anchor_tuple_or_time_unavailable");
    assert_eq!(report["scan_complete"], false);
    assert_eq!(report["integrity"]["invalid_records"], 1);
    assert!(!command(log.path(), "1").output().unwrap().status.success());
    assert!(
        !command(log.path(), "0")
            .args(SCOPE)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        !command(log.path(), "1")
            .args(SCOPE)
            .args(["--alert-id", "1"])
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[test]
fn related_search_recovers_only_the_exact_archived_trigger_in_the_same_capture() {
    use packrat_tui::{net::packet::CaptureMetadata, storage::packet_archive::PacketArchive};
    let mut log = tempfile::NamedTempFile::new().unwrap();
    let folder = tempfile::tempdir().unwrap();
    let archive_path = folder.path().join("archive");
    let mut archive = PacketArchive::open(&archive_path).unwrap();
    let mut packet = packets::tcp(1, 100, 0x02, b"Private payload");
    let size = packet.bytes.len() as u32;
    packet.timestamp = 800.0;
    packet.capture = Some(CaptureMetadata {
        timestamp: None, captured_length: size, wire_length: size, link_type: 1,
        section_id: 0, interface_id: 0, interface_name: None, comments: Vec::new(),
    });
    let mut unreadable = packet.clone();
    unreadable.no = 3;
    unreadable.capture.as_mut().unwrap().captured_length = 1;
    archive.append_scoped("capture-a", &[packet.clone(), unreadable]).unwrap();
    packet.no = 2;
    archive.append_scoped("capture-b", &[packet]).unwrap();
    drop(archive);

    let matching = AlertFlow { source: "10.0.0.1:40000".parse().unwrap(),
        destination: "10.0.0.2:80".parse().unwrap(), ..flow() };
    for (id, frame, time, tuple) in [(1, 1, 1300., None), (2, 2, 800., None), (3, 3, 800., None),
        (4, 4, 801., Some(matching)), (5, 5, 1300., Some(matching))] {
        let mut row = record(id, time, tuple, "session-a", "capture-a");
        row["alert"]["packet_no"] = json!(frame);
        writeln!(log, "{row}").unwrap();
    }
    assert_eq!(run(log.path(), "1", &[])["status"], "anchor_tuple_or_time_unavailable");
    let args = ["--evidence-archive", archive_path.to_str().unwrap()];
    let report = run(log.path(), "1", &args);
    assert_eq!(report["status"], "sampled");
    assert_eq!(report["anchor_source"], "retained_trigger_frame");
    assert_eq!(report["anchor_frame"], 1);
    assert_eq!(report["anchor_flow"], json!(matching));
    assert_eq!(report["anchor_trigger_time"], 800.0);
    assert_eq!(report["matching_alerts_in_sample"], 1);
    assert_eq!(report["matches"][0]["alert_id"], 4);
    for id in ["2", "3"] {
        let report = run(log.path(), id, &args);
        assert_eq!(report["status"], "anchor_tuple_or_time_unavailable");
        assert!(report["anchor_source"].is_null());
    }
    assert_eq!(run(log.path(), "4", &["--evidence-archive", "/no-archive-needed"])["anchor_source"], "recorded_alert");
}

#[test]
fn related_search_distinguishes_log_only_matches_from_checked_trigger_headers() {
    use packrat_tui::{net::packet::CaptureMetadata, storage::packet_archive::PacketArchive};
    let mut log = tempfile::NamedTempFile::new().unwrap();
    let folder = tempfile::tempdir().unwrap();
    let archive_path = folder.path().join("archive");
    let mut archive = PacketArchive::open(&archive_path).unwrap();
    let packet = |frame, time| {
        let mut packet = packets::tcp(frame, 100, 0x02, b"Private payload");
        let size = packet.bytes.len() as u32;
        packet.timestamp = time;
        packet.capture = Some(CaptureMetadata {
            timestamp: None, captured_length: size, wire_length: size, link_type: 1,
            section_id: 0, interface_id: 0, interface_name: None, comments: Vec::new(),
        });
        packet
    };
    let mut other_tuple = packet(4, 804.);
    other_tuple.bytes[34..36].copy_from_slice(&42_000_u16.to_be_bytes());
    let mut unreadable = packet(6, 806.);
    unreadable.capture.as_mut().unwrap().captured_length = 1;
    archive.append_scoped("capture-a", &[
        packet(1, 800.), packet(2, 802.), other_tuple, packet(5, 805.5), unreadable,
    ]).unwrap();
    archive.append_scoped("capture-b", &[packet(3, 803.)]).unwrap();
    drop(archive);
    let matching = AlertFlow { source: "10.0.0.1:40000".parse().unwrap(),
        destination: "10.0.0.2:80".parse().unwrap(), ..flow() };
    for (id, frame, time) in [(1, 1, 800.), (2, 2, 802.), (3, 3, 803.), (4, 4, 804.),
        (5, 5, 805.), (6, 6, 806.), (7, 0, 807.)] {
        let mut row = record(id, time, (id > 1).then_some(matching), "session-a", "capture-a");
        row["alert"]["packet_no"] = json!(frame);
        writeln!(log, "{row}").unwrap();
    }
    let archive = archive_path.to_str().unwrap();
    let unverified = run(log.path(), "1", &["--evidence-archive", archive]);
    assert!(unverified.get("anchor_trigger_evidence").is_none());
    assert!(unverified["matches"][0].get("trigger_evidence").is_none());
    let args = ["--evidence-archive", archive, "--verify-trigger-frames"];
    let report = run(log.path(), "1", &args);
    assert_eq!(report["anchor_trigger_evidence"], json!({"frame_number":1,"status":"derived_from_wire"}));
    assert_eq!(report["matching_alerts_in_sample"], 6);
    let statuses: Vec<_> = report["matches"].as_array().unwrap().iter()
        .map(|record| record["trigger_evidence"]["status"].as_str().unwrap()).collect();
    assert_eq!(statuses, ["matches_wire", "missing_frame", "tuple_differs_from_wire", "timestamp_differs_from_wire", "header_unavailable", "not_referenced"]);
    assert_eq!(run(log.path(), "2", &args)["anchor_trigger_evidence"]["status"], "matches_wire");
    assert!(!command(log.path(), "2").args(SCOPE).arg("--verify-trigger-frames").output().unwrap().status.success());
}

#[test]
fn cited_flow_search_pivots_beyond_the_trigger_and_reports_incomplete_evidence() {
    use packrat_tui::{net::packet::CaptureMetadata, storage::packet_archive::PacketArchive};
    let mut log = tempfile::NamedTempFile::new().unwrap();
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("archive");
    let mut archive = PacketArchive::open(&path).unwrap();
    let packet = |frame, time, port: u16| {
        let mut packet = packets::tcp(frame, 100, 0x02, b"Private payload");
        let size = packet.bytes.len() as u32;
        packet.bytes[36..38].copy_from_slice(&port.to_be_bytes());
        packet.timestamp = time;
        packet.capture = Some(CaptureMetadata {
            timestamp: None, captured_length: size, wire_length: size, link_type: 1,
            section_id: 0, interface_id: 0, interface_name: None, comments: Vec::new(),
        });
        packet
    };
    let mut unreadable = packet(4, 1130., 81);
    unreadable.capture.as_mut().unwrap().captured_length = 1;
    archive.append_scoped("capture-a", &[
        packet(1, 1000., 80), packet(2, 1100., 81), packet(3, 1120., 81), unreadable,
    ]).unwrap();
    archive.append_scoped("capture-b", &[packet(5, 1140., 81)]).unwrap();
    drop(archive);
    let first = AlertFlow { source: "10.0.0.1:40000".parse().unwrap(),
        destination: "10.0.0.2:80".parse().unwrap(), ..flow() };
    let second = AlertFlow { destination: "10.0.0.2:81".parse().unwrap(), ..first };
    let reverse = AlertFlow { source: second.destination, destination: second.source, ..second };
    let mut anchor = record(1, 1000., Some(first), "session-a", "capture-a");
    anchor["alert"]["packet_refs"] = json!([1, 2, 3, 4, 5]);
    writeln!(log, "{anchor}").unwrap();
    for (id, time, tuple, scope) in [(2, 1119., reverse, "capture-a"), (3, 1110., second, "capture-a"),
        (4, 1500., second, "capture-a"), (5, 1004., first, "capture-a"), (6, 1120., second, "capture-b")] {
        writeln!(log, "{}", record(id, time, Some(tuple), "session-a", scope)).unwrap();
    }
    let mut no_frames = record(7, 1000., Some(first), "session-a", "capture-a");
    for key in ["packet_no", "first_packet", "last_packet"] { no_frames["alert"][key] = json!(10); }
    no_frames["alert"]["packet_refs"] = json!([10]);
    writeln!(log, "{no_frames}").unwrap();

    let report = run(log.path(), "1", &[]);
    assert_eq!(report["matches"][0]["alert_id"], 7);
    assert_eq!(report["matching_alerts_in_sample"], 2);
    let args = ["--evidence-archive", path.to_str().unwrap(), "--match-cited-flows"];
    let report = run(log.path(), "1", &args);
    assert_eq!(report["cited_flow_evidence"], json!({
        "frames_examined":5,"usable_frames":3,"missing_frames":1,"header_unavailable_frames":1,
        "timestamp_unavailable_frames":0,"read_failed_frames":0,"omitted_frames":0,"directional_flows":2,
    }));
    let matches = report["matches"].as_array().unwrap();
    assert_eq!(matches.iter().map(|entry| entry["alert_id"].as_u64().unwrap()).collect::<Vec<_>>(), [7, 2, 5, 3]);
    assert_eq!(matches[1]["direction"], "reverse");
    assert_eq!(matches[1]["matched_cited_frame"], json!({"frame_number":3,"seconds_from_frame":-1.0}));
    assert_eq!(matches[3]["matched_cited_frame"], json!({"frame_number":2,"seconds_from_frame":10.0}));
    assert!(matches[1].get("seconds_from_anchor_trigger").is_none());
    let unavailable = run(log.path(), "7", &args);
    assert_eq!(unavailable["status"], "cited_flow_evidence_unavailable");
    assert_eq!(unavailable["matching_alerts_in_sample"], 0);
    assert!(!command(log.path(), "1").args(SCOPE).arg("--match-cited-flows").output().unwrap().status.success());
}

#[test]
fn caps_returned_matches_without_hiding_the_sample_count() {
    let mut log = tempfile::NamedTempFile::new().unwrap();
    for id in 1..=35 {
        writeln!(
            log,
            "{}",
            record(id, id as f64, Some(flow()), "session-a", "capture-a")
        )
        .unwrap();
    }
    let report = run(log.path(), "1", &[]);
    assert_eq!(report["matching_alerts_in_sample"], 34);
    let matches = report["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 32);
    assert_eq!(matches.last().unwrap()["alert_id"], 33);
}

#[test]
fn finds_older_anchor_beyond_unrelated_scope_churn_and_ignores_obsolete_matches() {
    let mut log = tempfile::NamedTempFile::new().unwrap();
    for (id, tuple) in [(1, Some(flow())), (2, Some(flow())), (3, Some(flow()))] {
        writeln!(log, "{}", record(id, 100., tuple, "session-a", "capture-a")).unwrap();
    }
    for id in 4..=620 {
        writeln!(
            log,
            "{}",
            record(id, 600., Some(flow()), "session-a", "capture-a")
        )
        .unwrap();
    }
    writeln!(log, "{}", record(3, 101., None, "session-a", "capture-a")).unwrap();
    let report = run(log.path(), "1", &[]);
    assert_eq!(report["status"], "sampled");
    assert_eq!(report["sampled_alerts"], 620);
    assert_eq!(report["scan_complete"], true);
    assert_eq!(report["matching_alerts_in_sample"], 1);
    assert_eq!(report["matches"][0]["alert_id"], 2);
}

#[test]
fn byte_budget_still_applies_even_when_no_recent_alerts_match_the_scope() {
    let dir = tempfile::tempdir().unwrap();
    let earlier = dir.path().join("earlier.jsonl");
    let active = dir.path().join("active.jsonl");
    std::fs::write(
        &earlier,
        record(1, 100., Some(flow()), "session-a", "capture-a").to_string(),
    )
    .unwrap();
    let mut log = std::fs::File::create(&active).unwrap();
    let mut unrelated = record(1, 100., Some(flow()), "session-b", "capture-a");
    unrelated["alert"]["detail"] = json!("x".repeat(900_000));
    let line = unrelated.to_string();
    for _ in 0..10 {
        writeln!(log, "{line}").unwrap();
    }
    let report = run(&active, "1", &["--previous-log", earlier.to_str().unwrap()]);
    assert_eq!(report["status"], "anchor_not_in_sample");
    assert_eq!(report["sampled_alerts"], 0);
    assert_eq!(report["scan_complete"], false);
    assert_eq!(report["integrity"]["stopped_at_scan_budget"], true);
}
