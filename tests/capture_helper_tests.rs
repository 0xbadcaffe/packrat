use packrat_tui::capture::helper::{decode_frame, write_frame, MAX_CAPTURE_FRAME};

#[test]
fn version_two_preserves_signed_clocks_wire_lengths_and_link_type() {
    use packrat_tui::capture::helper::{write_capture_frame, decode_capture_frame};
    use packrat_tui::net::packet::{CaptureMetadata, CaptureTimestamp, TimestampResolution};
    let metadata = CaptureMetadata {
        timestamp: Some(CaptureTimestamp { ticks: 1536, resolution: TimestampResolution::Binary(10), offset_seconds: -2 }),
        captured_length: 3, wire_length: 100, link_type: 101, interface_id: 7, section_id: 0,
        interface_name: None, comments: Vec::new(),
    };
    let mut encoded = Vec::new();
    write_capture_frame(&mut encoded, &metadata, &[1, 2, 3]).unwrap();
    let (decoded, bytes) = decode_capture_frame(&encoded).unwrap();
    assert_eq!(decoded, metadata);
    assert_eq!(bytes, [1, 2, 3]);
    let packet = packrat_tui::net::parser::parse_captured(bytes, 1, decoded).unwrap();
    assert_eq!(packet.protocol, "RAW");
    assert!(packet.src_port.is_none());
    for length in 0..encoded.len() {
        assert!(decode_capture_frame(&encoded[..length]).is_err());
    }
    encoded[28..32].copy_from_slice(&1u32.to_be_bytes());
    assert!(decode_capture_frame(&encoded).is_err());
}

#[tokio::test]
async fn helper_startup_failure_is_reported_to_the_caller() {
    use packrat_tui::capture::{CaptureSource, helper::HelperCapture};
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    let mut task = HelperCapture {
        program: std::env::temp_dir().join("packrat-missing-helper-9fa785f2"),
        iface: "test".into(),
        filter: None,
    }.run(tx);
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if let Some(result) = task.result() { break result; }
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    assert!(result.unwrap_err().contains("Start capture helper"));
}

#[tokio::test]
async fn dropping_capture_task_signals_blocking_worker_to_stop() {
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    let exited = Arc::new(AtomicBool::new(false));
    let worker_exited = exited.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let task = packrat_tui::capture::CaptureTask::blocking(move |stop| {
        let _ = started_tx.send(());
        while !stop.load(Ordering::Acquire) { std::thread::yield_now(); }
        worker_exited.store(true, Ordering::Release);
        Ok(())
    });
    started_rx.await.unwrap();
    drop(task);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !exited.load(Ordering::Acquire) { tokio::task::yield_now().await; }
    }).await.unwrap();
}

#[cfg(all(target_os = "linux", feature = "terminal-ui"))]
#[test]
fn archive_is_opened_only_after_filesystem_sandbox_activation() {
    let root = std::env::temp_dir().join(format!("packrat-sandbox-{}", rand::random::<u64>()));
    let allowed = root.join("allowed");
    let denied = root.join("denied");
    std::fs::create_dir_all(allowed.join("tmp")).unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_packrat"))
        .current_dir(&allowed)
        .env("TMPDIR", allowed.join("tmp"))
        .env("XDG_CONFIG_HOME", allowed.join("config"))
        .env("XDG_DATA_HOME", allowed.join("data"))
        .args(["--sandbox", "--simulation", "--archive"])
        .arg(&denied).output().unwrap();
    assert!(!result.status.success());
    assert!(!denied.exists(), "Archive directory was created before confinement");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn capture_helper_protocol_round_trips_timestamp_and_frame() {
    let mut encoded = Vec::new();
    write_frame(&mut encoded, 123_456, b"ethernet frame").unwrap();
    let (timestamp, frame) = decode_frame(&encoded).unwrap();
    assert_eq!(timestamp, 123_456);
    assert_eq!(frame, b"ethernet frame");
}

#[test]
fn capture_helper_protocol_rejects_truncation_and_oversize() {
    let mut truncated = Vec::new();
    truncated.extend_from_slice(&1_u64.to_be_bytes());
    truncated.extend_from_slice(&10_u32.to_be_bytes());
    truncated.extend_from_slice(b"short");
    assert!(decode_frame(&truncated).is_err());
    assert!(write_frame(Vec::new(), 0, &vec![0_u8; MAX_CAPTURE_FRAME + 1]).is_err());
}
