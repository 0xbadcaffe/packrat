use super::*;

#[test]
fn capture_loss_distinguishes_no_sample_from_zero_drops() {
    let loss = CaptureLoss::default();
    assert_eq!(loss.dropped(), None);
    loss.publish(Some(0));
    assert_eq!(loss.dropped(), Some(0));
    loss.publish(Some(u32::MAX));
    assert_eq!(loss.dropped(), Some(u32::MAX));
    loss.publish(None);
    assert_eq!(loss.dropped(), None);
}

#[tokio::test]
async fn blocking_capture_task_exposes_the_published_drop_count() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = CaptureTask::blocking_with_loss(move |_, loss| {
        loss.publish(Some(17));
        tx.send(()).unwrap();
        Ok(())
    });
    rx.await.unwrap();
    assert_eq!(task.pcap_buffer_drops(), Some(17));
}
