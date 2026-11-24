use super::*;

#[test]
fn saving_recovers_with_backfill_without_changing_the_preference() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("alerts.jsonl");
    let mut app = App::new_for_test();
    app.replace_core(AnalysisCore::default());
    app.save_alerts = true;
    app.alert_save_next_retry = None;
    app.configure_core(|core| {
        core.alert_center
            .record(1, "test", "HIGH", "First", "First retained alert");
    });
    let now = Instant::now();
    app.poll_alert_saving_with(now, |_| Err("temporary write failure".into()));
    assert!(app.save_alerts);
    assert!(
        app.query_core(|core| core.alert_save_error.is_some())
            .unwrap()
    );
    app.poll_alert_saving_with(now + Duration::from_secs(1), |_| panic!("retried too soon"));
    assert_eq!(app.query_core(|core| core.alert_save_failures), Some(1));
    app.configure_core(|core| {
        core.alert_center.items.clear(); // The first record now survives only in the retry queue.
        core.alert_center
            .record(2, "test", "HIGH", "Second", "Second retained alert");
    });
    let output = path.clone();
    app.poll_alert_saving_with(now + ALERT_SAVE_RETRY_INTERVAL, move |session| {
        AlertJsonlWriter::open(output, session)
    });
    assert!(
        app.query_core(|core| core.alert_jsonl_writer.is_some() && core.alert_save_error.is_none())
            .unwrap()
    );
    assert_eq!(app.query_core(|core| core.alert_save_failures), Some(1));
    assert_eq!(app.query_core(|core| core.alert_write_backlog.iter().count()), Some(0));
    let alerts: Vec<serde_json::Value> = std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0]["alert"]["packet_no"], 1);
    assert_eq!(alerts[1]["alert"]["packet_no"], 2);

    app.poll_alert_saving_with(now + ALERT_SAVE_RETRY_INTERVAL, |_| {
        panic!("already saving")
    });
    assert!(
        app.status_msg
            .as_deref()
            .unwrap()
            .contains("Alert saving restored")
    );
    app.toggle_alert_saving();
    assert!(!app.save_alerts);
    assert!(
        !app.query_core(|core| core.alert_jsonl_writer.is_some())
            .unwrap()
    );
    app.poll_alert_saving_with(now + ALERT_SAVE_RETRY_INTERVAL * 2, |_| panic!("disabled"));
}
