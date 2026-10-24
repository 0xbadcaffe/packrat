#![cfg(unix)]
use packrat_tui::analysis::helper_process::JsonLineHelper;
use std::{
    os::unix::fs::PermissionsExt,
    time::{Duration, Instant},
};

fn script(text: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("helper");
    std::fs::write(&path, format!("#!/bin/sh\n{text}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    (directory, path)
}

#[test]
fn a_nonresponding_helper_times_out_and_cannot_reuse_a_late_response() {
    let (_directory, path) = script("while IFS= read -r line; do while :; do :; done; done");
    let mut helper =
        JsonLineHelper::spawn_with_limits(path, "test", Duration::from_millis(50), 1024).unwrap();
    let start = Instant::now();
    let result: Result<serde_json::Value, _> = helper.request(&serde_json::json!({"request":1}));
    assert!(result.unwrap_err().contains("timeout"));
    assert!(start.elapsed() < Duration::from_secs(2));
    let result: Result<serde_json::Value, _> = helper.request(&serde_json::json!({"request":2}));
    assert!(result.unwrap_err().contains("earlier failure"));
}

#[test]
fn oversized_unterminated_and_invalid_json_responses_fail_closed() {
    for body in [
        "printf '%080d\\n' 0",
        "printf '{}'; exit",
        "printf 'invalid\\n'",
    ] {
        let (_directory, path) = script(&format!("while IFS= read -r line; do {body}; done"));
        let mut helper =
            JsonLineHelper::spawn_with_limits(path, "test", Duration::from_secs(1), 64).unwrap();
        let result: Result<serde_json::Value, _> = helper.request(&serde_json::json!({}));
        assert!(result.is_err());
    }
}

#[test]
fn helper_keeps_valid_request_response_pairs_on_one_process() {
    let (_directory, path) = script("while IFS= read -r line; do printf '%s\\n' \"$line\"; done");
    let mut helper = JsonLineHelper::spawn(path, "test").unwrap();
    for index in 0..10 {
        let request = serde_json::json!({"index":index});
        let response: serde_json::Value = helper.request(&request).unwrap();
        assert_eq!(response, request);
    }
}

#[test]
fn helper_limits_cannot_disable_the_hard_bounds() {
    for (timeout, limit) in [
        (Duration::ZERO, 1024),
        (Duration::from_secs(1), 0),
        (Duration::from_secs(1), 5 * 1024 * 1024),
    ] {
        assert!(
            JsonLineHelper::spawn_with_limits("/does/not/exist", "test", timeout, limit).is_err()
        );
    }
}
