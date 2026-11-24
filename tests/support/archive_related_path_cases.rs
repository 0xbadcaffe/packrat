use packrat_tui::{net::packet::CaptureMetadata, storage::packet_archive::PacketArchive};

use super::{AlertFlow, SCOPE, Write, command, flow, json, packets, record, run};

#[test]
fn strict_path_filter_searches_past_log_only_candidates_within_its_budget() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive");
    let mut log = tempfile::NamedTempFile::new().unwrap();
    let mut archive = PacketArchive::open(&path).unwrap();
    let timestamp = |frame| 800.0 + frame as f64;
    let packet = |frame, interface_id| {
        let mut packet = packets::tcp(frame, 1, 0x02, &[]);
        packet.timestamp = timestamp(frame);
        let size = packet.bytes.len() as u32;
        packet.capture = Some(CaptureMetadata {
            timestamp: None,
            captured_length: size,
            wire_length: size,
            link_type: 1,
            section_id: 0,
            interface_id,
            interface_name: None,
            comments: Vec::new(),
        });
        packet
    };
    archive
        .append_scoped(
            "capture-a",
            &[packet(1, 0), packet(50, 0), packet(51, 1), packet(132, 0)],
        )
        .unwrap();
    drop(archive);
    let matching = AlertFlow {
        source: "10.0.0.1:40000".parse().unwrap(),
        destination: "10.0.0.2:80".parse().unwrap(),
        ..flow()
    };
    for id in 1..=133 {
        let mut row = record(id, timestamp(id), Some(matching), "session-a", "capture-a");
        row["alert"]["packet_no"] = json!(id);
        writeln!(log, "{row}").unwrap();
    }
    let archive = path.to_str().unwrap();
    let normal = run(
        log.path(),
        "1",
        &["--evidence-archive", archive, "--verify-trigger-frames"],
    );
    assert_eq!(normal["matching_alerts_in_sample"], 132);
    assert_eq!(normal["matches"].as_array().unwrap().len(), 32);
    assert!(
        normal["matches"]
            .as_array()
            .unwrap()
            .iter()
            .all(|alert| alert["trigger_evidence"]["status"] == "missing_frame")
    );

    assert!(
        !command(log.path(), "1")
            .args(SCOPE)
            .arg("--require-verified-path")
            .output()
            .unwrap()
            .status
            .success()
    );
    let args = ["--evidence-archive", archive, "--require-verified-path"];
    let strict = run(log.path(), "1", &args);
    assert_eq!(strict["matching_alerts_in_sample"], 132);
    assert_eq!(strict["matches"].as_array().unwrap().len(), 1);
    assert_eq!(strict["matches"][0]["alert_id"], 50);
    assert_eq!(
        strict["matches"][0]["captured_path_comparison"],
        "same_observed_path"
    );
    assert_eq!(
        strict["verified_path_filter"],
        json!({
            "examined_candidates":128,"same_observed_path":1,"different_observed_path":1,
            "path_unavailable":126,"unchecked_candidates":4
        })
    );

    let no_reference = run(log.path(), "2", &args);
    assert_eq!(no_reference["status"], "reference_path_unverified");
    assert_eq!(no_reference["matches"], json!([]));

    let cited = run(
        log.path(),
        "1",
        &[
            "--evidence-archive",
            archive,
            "--require-verified-path",
            "--match-cited-flows",
        ],
    );
    assert_eq!(
        cited["verified_path_filter"],
        strict["verified_path_filter"]
    );
    assert_eq!(
        cited["matches"][0]["matched_cited_frame"]["frame_number"],
        1
    );
}
