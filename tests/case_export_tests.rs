#![cfg(feature = "terminal-ui")]

#[path = "support/packets.rs"]
mod packets;

use packrat_tui::analysis::case_export::export;
use packrat_tui::app::App;
use packrat_tui::storage::packet_archive::ArchiveWorker;

#[test]
fn case_report_preserves_scoped_finding_evidence_and_rule_version() {
    let temporary = tempfile::tempdir().unwrap();
    let mut app = App::new_for_test();
    app.set_packet_archive(ArchiveWorker::open(&temporary.path().join("archive")).unwrap())
        .unwrap();
    app.inject_packet(packets::tcp(1, 100, 0x04, b""));
    app.inject_packet(packets::tcp(2, 101, 0x18, b"not-in-the-case-report"));
    let scope = app
        .query_core(|core| core.alert_center.items[0].capture_id.clone())
        .unwrap()
        .unwrap();

    let report = temporary.path().join("case.json");
    export(&app, &report).unwrap();
    let contents = std::fs::read_to_string(&report).unwrap();
    let document: serde_json::Value = serde_json::from_str(&contents).unwrap();
    let finding = &document["findings"][0];
    assert_eq!(finding["capture_id"], scope);
    assert_eq!(finding["packet_no"], 2);
    assert_eq!(finding["packet_refs"], serde_json::json!([1, 2]));
    assert_eq!(
        finding["provenance"]["rule_id"],
        "tcp.payload_after_observed_reset"
    );
    assert_eq!(finding["provenance"]["revision"], 11);
    assert_eq!(finding["provenance"]["confidence"], "heuristic");
    assert!(!contents.contains("not-in-the-case-report"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&report).unwrap().permissions().mode() & 0o077,
            0
        );
    }
}

#[test]
fn case_report_does_not_replace_an_existing_file() {
    let temporary = tempfile::tempdir().unwrap();
    let report = temporary.path().join("case.json");
    std::fs::write(&report, b"original report").unwrap();
    assert!(export(&App::new_for_test(), &report).is_err());
    assert_eq!(std::fs::read(&report).unwrap(), b"original report");
    assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 1);
}
