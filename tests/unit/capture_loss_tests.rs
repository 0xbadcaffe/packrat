use super::*;

#[test]
fn capture_loss_distinguishes_no_sample_from_zero_drops() {
    let loss = CaptureStats::default();
    assert_eq!(loss.dropped(), None);
    loss.publish_drops(Some(0));
    assert_eq!(loss.dropped(), Some(0));
    loss.publish_drops(Some(u32::MAX));
    assert_eq!(loss.dropped(), Some(u32::MAX));
    loss.publish_drops(None);
    assert_eq!(loss.dropped(), None);
}

#[tokio::test]
async fn blocking_capture_task_exposes_the_published_drop_count() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = CaptureTask::blocking_with_stats(move |_, stats| {
        stats.publish_drops(Some(17));
        stats.publish_link_type(0);
        tx.send(()).unwrap();
        Ok(())
    });
    rx.await.unwrap();
    assert_eq!(task.pcap_buffer_drops(), Some(17));
    assert_eq!(task.link_type(), Some(0));
}

#[tokio::test]
async fn capture_truncation_is_independent_of_kernel_drops() {
    let unavailable = CaptureTask::spawn(async { Ok(()) });
    assert_eq!(unavailable.truncated_frames(), None);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = CaptureTask::blocking_with_stats(move |_, stats| {
        stats.publish_link_type(1);
        stats.publish_drops(Some(0));
        stats.observe_frame_lengths(64, 64).unwrap();
        assert!(stats.observe_frame_lengths(64, 60).is_err());
        stats.observe_frame_lengths(60, 64).unwrap();
        stats.observe_frame_lengths(0, 64).unwrap();
        tx.send(()).unwrap();
        Ok(())
    });
    rx.await.unwrap();
    assert_eq!(task.pcap_buffer_drops(), Some(0));
    assert_eq!(task.truncated_frames(), Some(2));
}
