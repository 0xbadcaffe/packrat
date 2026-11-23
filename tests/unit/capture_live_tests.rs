use super::*;

#[test]
fn a_full_queue_counts_the_packet_once_without_dropping_or_reordering_it() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let stop = std::sync::atomic::AtomicBool::new(false);
    let stats = CaptureStats::default();
    assert!(send_with_backpressure(&tx, 1, &stop, &stats, || panic!("queue was empty")));
    let mut retries = 0;
    assert!(send_with_backpressure(&tx, 2, &stop, &stats, || {
        retries += 1;
        if retries == 3 { assert_eq!(rx.try_recv().unwrap(), 1); }
    }));
    assert_eq!(retries, 3);
    assert_eq!(rx.try_recv().unwrap(), 2);
    assert_eq!(stats.queue_full_packets.load(Ordering::Relaxed), 1);
}

#[test]
fn missing_capture_device_returns_an_error_without_panicking() {
    let source = LiveCapture {
        iface: "packrat-device-that-does-not-exist".into(),
        filter: None,
        timeout_ms: crate::storage::theme_store::DEFAULT_CAPTURE_TIMEOUT_MS,
    };
    assert!(open_capture(&source).is_err());
}

#[test]
fn live_packet_export_preserves_interface_across_seconds() {
    let path = std::env::temp_dir().join(format!("packrat-live-{}.pcapng", rand::random::<u64>()));
    let clocks = [
        pcap_timestamp(1_795_286_117, 999_999).unwrap(),
        pcap_timestamp(1_795_286_118, 0).unwrap(),
    ];
    {
        let mut writer = crate::export::pcapng::PcapNgWriter::create(&path).unwrap();
        for (index, clock) in clocks.into_iter().enumerate() {
            let packet = parse_captured(&[0; 14], index as u64 + 1, CaptureMetadata {
                timestamp: Some(clock),
                captured_length: 14,
                wire_length: 14,
                link_type: 1,
                interface_id: 0,
                section_id: 0,
                interface_name: Some("test0".into()),
                comments: Vec::new(),
            }).unwrap();
            writer.write_packet(&packet).unwrap();
        }
        writer.flush().unwrap();
    }
    let restored = crate::pcap_replay::read_pcap(&path);
    std::fs::remove_file(path).unwrap();
    let restored = restored.unwrap();
    assert_eq!(restored.len(), 2);
    for (packet, clock) in restored.iter().zip(clocks) {
        let capture = packet.capture.as_ref().unwrap();
        assert_eq!(capture.interface_id, 0);
        assert_eq!(capture.timestamp, Some(clock));
    }
    assert_eq!(clocks[0].nanoseconds(), 1_795_286_117_999_999_000);
    assert_eq!(clocks[1].nanoseconds() - clocks[0].nanoseconds(), 1000);
}

#[test]
fn live_clock_rejects_invalid_values_and_preserves_pre_epoch_time() {
    assert!(pcap_timestamp(0, -1).is_err());
    assert!(pcap_timestamp(0, 1_000_000).is_err());
    assert!(pcap_timestamp(i64::MAX, 0).is_err());
    assert_eq!(pcap_timestamp(-1, 500_000).unwrap().nanoseconds(), -500_000_000);
}
