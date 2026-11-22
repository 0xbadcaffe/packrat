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
