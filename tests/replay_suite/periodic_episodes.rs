use super::{CaptureMetadata, CaptureTimestamp, PcapNgWriter, TimestampResolution, Value, json, run_suite, support};

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn replay_separates_periodic_episodes_after_directional_expiry_but_not_a_continuous_run() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let rule = "traffic.periodic_fixed_size";
    let mut cases = Vec::new();
    for (file, second_start, reverse_ticks, expected) in [
        ("continuous.pcapng", 70, &[][..], vec![7]),
        ("renewed.pcapng", 3661, &[][..], vec![7, 14]),
        ("reverse-background.pcapng", 3661, &[1000, 2750, 3650][..], vec![7, 17]),
    ] {
        let mut writer = PcapNgWriter::create(&root.join(file)).unwrap();
        let schedule = (0..7).map(|i| (i * 10, false))
            .chain(reverse_ticks.iter().map(|&tick| (tick, true)))
            .chain((0..7).map(|i| (second_start + i * 10, false)));
        for (index, (ticks, reverse)) in schedule.enumerate() {
            let frame = index as u64 + 1;
            let mut packet = support::tcp(frame, 10 + index as u32 * 12, 0x18, &[1_u8; 12], reverse);
            let length = packet.bytes.len() as u32;
            packet.capture = Some(CaptureMetadata {
                timestamp: Some(CaptureTimestamp {
                    ticks,
                    resolution: TimestampResolution::Decimal(0), offset_seconds: 0,
                }),
                captured_length: length, wire_length: length, link_type: 1,
                interface_id: 0, section_id: 0, interface_name: None, comments: Vec::new(),
            });
            writer.write_packet(&packet).unwrap();
        }
        writer.flush().unwrap();
        let opening_evidence: Vec<_> = expected.iter().map(|&opening_frame| json!({
            "rule_id":rule,"opening_frame":opening_frame,"frames":(opening_frame - 6..=opening_frame).collect::<Vec<_>>()
        })).collect();
        cases.push(json!({"name":file,"capture":file,"expect_counts":{(rule):expected.len()},
            "opening_frames":{(rule):expected},"opening_evidence":opening_evidence,"expect_snapshots":expected.len()}));
    }
    let manifest = root.join("periodic-episodes.json");
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":cases}).to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 3);
}
