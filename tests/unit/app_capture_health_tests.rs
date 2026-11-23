use super::*;

#[tokio::test]
async fn capture_counters_advance_while_the_analysis_core_is_locked() {
    let mut app = App::new_for_test();
    let (send, receive) = tokio::sync::oneshot::channel();
    app.capture_handle = Some(CaptureTask::blocking_with_stats(move |_, stats| {
        stats.publish_link_type(1);
        stats.publish_drops(Some(0));
        assert!(send.send(stats).is_ok());
        Ok(())
    }));
    let stats = receive.await.unwrap();
    app.refresh_telemetry();
    assert_eq!(app.telemetry.snapshot().capture_queue_full_packets, Some(0));

    let core = app.core.clone();
    let _locked = core.edit();
    stats.observe_queue_full();
    stats.observe_frame_lengths(59, 60).unwrap();
    stats.publish_drops(Some(2));
    app.refresh_telemetry();
    let snapshot = app.telemetry.snapshot();
    assert_eq!(snapshot.capture_queue_full_packets, Some(1));
    assert_eq!(snapshot.capture_truncated_frames, Some(1));
    assert_eq!(snapshot.pcap_buffer_drops, Some(2));
}
