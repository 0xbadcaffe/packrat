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
fn a_failed_append_disables_saving_without_losing_the_in_memory_alert() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("alerts.jsonl");
    let worker = AnalysisWorker::spawn(core_with_writer(&path), WorkerLimits::default()).unwrap();
    worker
        .try_update(1, |core| {
            core.alert_center
                .record(1, "IDS", "HIGH", "Observed", "x".repeat(1_048_576));
            Ok(())
        })
        .unwrap();
    let core = worker.finish(|_| ()).unwrap();
    assert!(core.alert_jsonl_writer.is_none());
    assert!(
        core.alert_save_error
            .as_deref()
            .unwrap()
            .contains("export size limit")
    );
    assert_eq!(core.alert_center.items.len(), 1);
    assert_eq!(std::fs::metadata(path).unwrap().len(), 0);
}
