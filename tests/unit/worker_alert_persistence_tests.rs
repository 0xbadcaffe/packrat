use super::*;
use crate::storage::alert_jsonl::AlertJsonlWriter;

fn core_with_writer(path: &std::path::Path) -> AnalysisCore {
    let mut core = AnalysisCore::default();
    let writer = AlertJsonlWriter::open(path.to_owned(), "test-session").unwrap();
    core.alert_jsonl_writer = Some(Arc::new(Mutex::new(writer)));
    core
}

#[test]
fn alert_writes_do_not_hold_the_analysis_core_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("alerts.jsonl");
    let core = core_with_writer(&path);
    let writer = core.alert_jsonl_writer.as_ref().unwrap().clone();
    let blocked = writer.lock().unwrap();
    let worker = AnalysisWorker::spawn(core, WorkerLimits::default()).unwrap();
    let view = worker.read_core();
    let (started, reached) = mpsc::sync_channel(1);
    worker
        .try_update(1, move |core| {
            core.alert_center
                .record(1, "IDS", "HIGH", "Observed", "test finding");
            started.send(()).unwrap();
            Ok(())
        })
        .unwrap();
    reached.recv_timeout(Duration::from_secs(3)).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(snapshot) = view.try_read().unwrap() {
            assert_eq!(snapshot.alert_center.items.len(), 1);
            assert!(snapshot.alert_jsonl_writer.is_some());
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "writer blocked the core"
        );
        std::thread::yield_now();
    }
    assert!(worker.try_event().unwrap().is_none());
    drop(view);
    drop(blocked);
    worker.finish(|_| ()).unwrap();
    assert_eq!(std::fs::read_to_string(path).unwrap().lines().count(), 1);
}

#[test]
fn oversized_descriptions_do_not_block_subsequent_alerts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("alerts.jsonl");
    let worker = AnalysisWorker::spawn(core_with_writer(&path), WorkerLimits::default()).unwrap();
    worker
        .try_update(1, |core| {
            core.alert_center
                .record(1, "IDS", "HIGH", "Observed", "\u{1f50d}\0".repeat(150_000));
            core.alert_center.record(2, "IDS", "HIGH", "Later", "ordinary alert");
            Ok(())
        })
        .unwrap();
    let core = worker.finish(|_| ()).unwrap();
    assert!(core.alert_jsonl_writer.is_some());
    assert!(core.alert_save_error.is_none());
    assert_eq!(core.alert_save_failures, 0);
    assert_eq!(core.alert_center.items[0].detail.len(), 750_000);
    let records: Vec<serde_json::Value> = std::fs::read_to_string(path).unwrap()
        .lines().map(|row| serde_json::from_str(row).unwrap()).collect();
    assert_eq!(records.len(), 2);
    assert!(records[0]["alert"]["detail"].as_str().unwrap().starts_with("[Truncated] "));
    assert_eq!(records[0]["alert"]["packet_refs"], serde_json::json!([1]));
    assert_eq!(records[1]["alert"]["detail"], "ordinary alert");
}

#[cfg(unix)]
#[test]
fn a_failed_append_disables_saving_without_losing_the_in_memory_alert() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("alerts.jsonl");
    let core = core_with_writer(&path);
    let renamed = dir.path().join("previous.jsonl");
    std::fs::rename(&path, &renamed).unwrap();
    std::os::unix::fs::symlink(&renamed, &path).unwrap();
    let worker = AnalysisWorker::spawn(core, WorkerLimits::default()).unwrap();
    worker.try_update(1, |core| {
        core.alert_center.record(1, "IDS", "HIGH", "Observed", "normal detail");
        Ok(())
    }).unwrap();
    worker.try_update(2, |core| {
        core.alert_center.record(2, "IDS", "HIGH", "During outage", "new detail");
        Ok(())
    }).unwrap();
    let core = worker.finish(|_| ()).unwrap();
    assert!(core.alert_jsonl_writer.is_none());
    assert!(core.alert_save_error.is_some());
    assert_eq!(core.alert_save_failures, 1);
    assert_eq!(core.alert_center.items.len(), 2);
    assert_eq!(core.alert_write_backlog.iter().map(|alert| alert.packet_no).collect::<Vec<_>>(), [1, 2]);
    assert_eq!(std::fs::metadata(path).unwrap().len(), 0);
}
