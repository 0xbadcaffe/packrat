#![cfg(unix)]
#[path = "support/http3_control.rs"]
mod control;
#[path = "support/http3_push.rs"]
mod push_fixture;
#[path = "support/http3.rs"]
mod support;
use packrat_tui::analysis::transactions::http3::Http3Sender::Client;
use packrat_tui::{analysis::quic_scope::QuicScope, export::pcapng::PcapNgWriter};
use support::*;

#[test]
fn helper_authentication_is_required_before_any_http3_event_is_retained() {
    for ok in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let program = helper(
            directory.path(),
            &serde_json::json!({"ok": ok, "http3": batch(vec![header_event(Client, 0, request()), finished(Client, 10)])}),
        );
        let mut scope = QuicScope::default();
        scope.decode_helper_path = Some(program);
        scope.ingest(&quic_packet(1));
        assert_eq!(scope.http3.connection_ids().count(), usize::from(ok));
        assert_eq!(scope.decode_errors, u64::from(!ok));
        if !ok {
            assert!(
                scope
                    .last_decode_error
                    .as_ref()
                    .unwrap()
                    .contains("authenticate")
            );
        }
        scope.clear();
        assert_eq!(scope.http3.connection_ids().count(), 0);
    }
}

#[test]
fn structured_helper_contract_rejects_bad_metadata_and_oversized_frame_details() {
    for response in [
        serde_json::json!({"ok": true, "http3": {"connection_id":"id", "alpn":"h2", "events":[]}}),
        serde_json::json!({"ok": true, "frames":[{"frame_type":"data", "detail":"x".repeat(513)}]}),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let program = helper(directory.path(), &response);
        let mut scope = QuicScope::default();
        scope.decode_helper_path = Some(program);
        scope.ingest(&quic_packet(1));
        assert_eq!(scope.decode_errors, 1);
        assert_eq!(scope.http3.connection_ids().count(), 0);
        assert!(scope.all()[0].decoded_frames.is_empty());
    }
}

#[test]
fn headless_http3_decoding_requires_explicit_helper_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let program = helper(
        directory.path(),
        &serde_json::json!({"ok": true, "http3": batch(vec![header_event(Client, 0, request()), finished(Client, 10)])}),
    );
    let path = directory.path().join("quic.pcapng");
    let mut writer = PcapNgWriter::create(&path).unwrap();
    writer.write_packet(&quic_packet(1)).unwrap();
    writer.flush().unwrap();
    for configured in [false, true] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_packrat-analyze"));
        if configured {
            command.arg("--quic-decode-helper").arg(&program);
        }
        let output = command
            .arg(&path)
            .env("HOME", "/nonexistent")
            .env_remove("TERM")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let events: Vec<serde_json::Value> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            events
                .iter()
                .any(|event| event["type"] == "http3_conversation"),
            configured
        );
        let summary = events
            .iter()
            .find(|event| event["type"] == "summary")
            .unwrap();
        assert_eq!(summary["http3_exchanges"], usize::from(configured));
        assert_eq!(summary["containment"], "disabled");
        assert_eq!(summary["quic_decode_errors"], 0);
    }
}

#[test]
fn headless_helper_options_reject_missing_duplicate_and_unknown_options() {
    for args in [
        vec!["--quic-decode-helper"],
        vec![
            "--quic-decode-helper",
            "one",
            "--quic-decode-helper",
            "two",
            "capture",
        ],
        vec!["capture", "extra"],
        vec!["--contain", "capture"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn headless_reports_authenticated_control_and_pushes_without_enabling_containment() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("push.pcapng");
    let mut writer = PcapNgWriter::create(&path).unwrap();
    writer.write_packet(&quic_packet(1)).unwrap();
    writer.flush().unwrap();
    for ok in [false, true] {
        let program = helper(
            directory.path(),
            &serde_json::json!({"ok":ok, "http3":batch(push_fixture::exchange())}),
        );
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
            .arg("--quic-decode-helper")
            .arg(program)
            .arg(&path)
            .env("HOME", "/nonexistent")
            .env_remove("TERM")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let events: Vec<serde_json::Value> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let summary = events
            .iter()
            .find(|event| event["type"] == "summary")
            .unwrap();
        assert_eq!(summary["http3_pushes"], usize::from(ok));
        assert_eq!(summary["http3_control_streams"], usize::from(ok));
        assert_eq!(summary["quic_decode_errors"], usize::from(!ok));
        assert_eq!(summary["containment"], "disabled");
        if ok {
            let report = &events
                .iter()
                .find(|event| event["type"] == "http3_conversation")
                .unwrap()["conversation"];
            assert_eq!(report["control_streams"][0]["max_push_id"], 0);
            assert_eq!(report["pushes"][0]["state"], "Complete");
            assert_eq!(report["pushes"][0]["streams"][0]["stream_id"], 7);
            assert_eq!(
                report["pushes"][0]["streams"][0]["response"]["body"][0]["data"],
                serde_json::json!(b"ok".as_slice())
            );
        } else {
            assert!(
                !events
                    .iter()
                    .any(|event| event["type"] == "http3_conversation")
            );
        }
    }
}
