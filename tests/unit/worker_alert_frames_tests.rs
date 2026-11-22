use super::*;

fn packet(frame: u64, size: usize) -> Packet {
    crate::net::parser::parse_ethernet(&vec![0; size], frame, frame as f64)
}

#[test]
fn worker_handoff_keeps_only_referenced_frames_and_is_opt_in() {
    let mut core = AnalysisCore::default();
    core.alert_center.capture_id = Some("current".into());
    core.alert_center.record_correlated_with_evidence(
        (4, &[1, 3]), 4.0, "TEST", "HIGH", "Current finding", "observation", "current",
    );
    core.alert_center.capture_id = Some("old".into());
    core.alert_center.record_correlated_with_evidence(
        (2, &[]), 2.0, "TEST", "HIGH", "Old finding", "observation", "old",
    );
    core.alert_center.capture_id = Some("current".into());
    let analysis = PacketAnalysis { alert_pins: vec![1, 2], ..Default::default() };
    let history = VecDeque::from([packet(1, 14), packet(2, 15), packet(3, 16)]);
    let trigger = packet(4, 17);
    assert!(alert_frames(&core, &analysis, &trigger, &history).is_empty());
    core.alert_center.archive_alert_packets = true;
    let frames = alert_frames(&core, &analysis, &trigger, &history);
    assert_eq!(frames.iter().map(|p| p.no).collect::<Vec<_>>(), [1, 3, 4]);
    assert_eq!(frames[2].bytes, trigger.bytes);
}

#[test]
fn worker_handoff_prioritizes_trigger_and_bounds_payload_and_frame_count() {
    let mut core = AnalysisCore::default();
    core.alert_center.capture_id = Some("current".into());
    core.alert_center.archive_alert_packets = true;
    let references: Vec<_> = (1..=40).collect();
    core.alert_center.record_correlated_with_evidence(
        (41, &references), 41.0, "TEST", "CRITICAL", "Finding", "observation", "flow",
    );
    let analysis = PacketAnalysis { alert_pins: vec![1], ..Default::default() };
    let trigger = packet(41, 64 * 1024);
    let history: VecDeque<_> = (1..=40).map(|n| packet(n, 64 * 1024)).collect();
    let frames = alert_frames(&core, &analysis, &trigger, &history);
    assert_eq!(frames.iter().map(|p| p.no).collect::<Vec<_>>(), [38, 39, 40, 41]);
    assert_eq!(frames.iter().map(|p| p.bytes.len()).sum::<usize>(), MAX_BYTES);

    let history: VecDeque<_> = (1..=40).map(|n| packet(n, 14)).collect();
    let frames = alert_frames(&core, &analysis, &trigger, &history);
    assert_eq!(frames.len(), MAX_FRAMES);
    assert_eq!(frames.last().unwrap().no, 41);
}
