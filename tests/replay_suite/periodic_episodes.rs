use super::{CaptureMetadata, CaptureTimestamp, PcapNgWriter, TimestampResolution, Value, json, run_suite, support};

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn periodic_replay_distinguishes_fresh_tcp_segments_from_partial_retransmissions() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let rule = "traffic.periodic_fixed_size";
    let mut cases = Vec::new();
    for (name, flags, sequence_step, expected) in [
        ("partial-retries", 0x18, 1, 0),
        ("opening-control-with-data", 0x12, 16, 0),
        ("fresh-segments", 0x18, 16, 1),
    ] {
        let file = format!("{name}.pcapng");
        let mut writer = PcapNgWriter::create(&root.join(&file)).unwrap();
        for index in 0..7_u32 {
            let mut packet = support::tcp(u64::from(index) + 1, 100 + index * sequence_step, flags, &[1; 16], false);
            packet.timestamp = f64::from(index) * 15.0;
            writer.write_packet(&packet).unwrap();
        }
        writer.flush().unwrap();
        let mut case = json!({
            "name":name, "capture":file, "expect_counts":{(rule):expected},
            "expect_snapshots":expected,
        });
        if expected == 1 {
            case["opening_frames"] = json!({(rule):[7]});
            case["opening_evidence"] = json!([{
                "rule_id":rule, "opening_frame":7, "frames":[1, 2, 3, 4, 5, 6, 7],
                "classification":{"severity":"MEDIUM","confidence":"heuristic","revision":14},
            }]);
        }
        cases.push(case);
    }
    let manifest = root.join("periodic-tcp-retries.json");
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":cases}).to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn replay_separates_periodic_episodes_after_directional_expiry_but_not_a_continuous_run() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let rule = "traffic.periodic_fixed_size";
    let mut cases = Vec::new();
    for (file, second_start, background_ticks, background_reverse, expected) in [
        ("continuous.pcapng", 70, &[][..], false, vec![7]),
        ("renewed.pcapng", 3661, &[][..], false, vec![7, 14]),
        ("reverse-background.pcapng", 3661, &[1000, 2750, 3650][..], true, vec![7, 17]),
        ("same-direction-background.pcapng", 3661, &[1000, 2750, 3650][..], false, vec![7, 17]),
    ] {
        let mut writer = PcapNgWriter::create(&root.join(file)).unwrap();
        let schedule = (0..7).map(|i| (i * 10, false, 12))
            .chain(background_ticks.iter().map(|&tick| (tick, background_reverse, 120)))
            .chain((0..7).map(|i| (second_start + i * 10, false, 12)));
        for (index, (ticks, reverse, payload_size)) in schedule.enumerate() {
            let frame = index as u64 + 1;
            let mut packet = support::tcp(frame, 10 + index as u32 * 120, 0x18, &vec![1_u8; payload_size], reverse);
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
    assert_eq!(report["passed"], 4);
}
