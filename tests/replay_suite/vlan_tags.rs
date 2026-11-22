use super::{CaptureMetadata, CaptureTimestamp, Command, PcapNgWriter, TimestampResolution, Value, arp, json, run_suite};

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn stacked_vlan_replay_distinguishes_wire_observation_from_inferred_hopping() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let rule = "vlan.tag_stack_observed";
    let mut cases = Vec::new();
    for (name, interfaces, openings) in [
        ("ordinary-single-tag", &[0][..], &[][..]),
        ("truncated-tag-header", &[0][..], &[][..]),
        ("more-than-two-tags", &[0][..], &[][..]),
        ("provider-tag-stack", &[0, 0, 1][..], &[1, 3][..]),
    ] {
        let capture = format!("{name}.pcapng");
        let mut writer = PcapNgWriter::create(&root.join(&capture)).unwrap();
        for (index, &interface_id) in interfaces.iter().enumerate() {
            let frame = index as u64 + 1;
            let mut packet = arp::reply(frame, frame as f64, 20, 1);
            if name != "ordinary-single-tag" {
                packet.bytes.splice(12..12, [0x88, 0xa8, 0, 100]);
            }
            if name == "truncated-tag-header" {
                packet.bytes.truncate(20);
            } else if name == "more-than-two-tags" {
                packet.bytes.splice(20..20, [0x81, 0, 0, 30]);
            }
            let length = packet.bytes.len() as u32;
            packet.length = length as u16;
            packet.capture = Some(CaptureMetadata {
                timestamp: Some(CaptureTimestamp { ticks: frame, resolution: TimestampResolution::Decimal(0), offset_seconds: 0 }),
                captured_length: length, wire_length: length, link_type: 1,
                section_id: 0, interface_id, interface_name: None, comments: Vec::new(),
            });
            writer.write_packet(&packet).unwrap();
        }
        writer.flush().unwrap();
        let mut case = json!({"name":name,"capture":capture,"expect_counts":{(rule):openings.len()},
            "expect_snapshots":openings.len()});
        if !openings.is_empty() {
            case["opening_frames"] = json!({(rule):openings});
            case["opening_evidence"] = json!(openings.iter().map(|&frame| {
                json!({"rule_id":rule,"opening_frame":frame,"frames":[frame]})
            }).collect::<Vec<_>>());
        }
        cases.push(case);
    }
    let manifest = root.join("vlan.json");
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":cases}).to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    assert_eq!(serde_json::from_slice::<Value>(&output.stdout).unwrap()["passed"], 4);

    let findings = Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
        .arg("--alerts-only").arg(root.join("provider-tag-stack.pcapng")).output().unwrap();
    assert!(findings.status.success());
    let alerts: Vec<_> = String::from_utf8(findings.stdout).unwrap().lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|row| row["type"] == "alert").collect();
    assert_eq!(alerts.len(), 2);
    assert!(alerts.iter().all(|row| row["alert"]["severity"] == "INFO"));
    let detail = alerts[1]["alert"]["detail"].as_str().unwrap();
    assert!(detail.contains("outer VLAN 100 (0x88a8) and inner VLAN 20 (0x8100)"));
    assert!(detail.contains("interface 1; port policy and forwarding are unverified"));
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn single_tag_policy_replay_requires_an_exact_named_interface() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let capture = root.join("mixed.pcapng");
    let mut writer = PcapNgWriter::create(&capture).unwrap();
    for (frame, interface_id, name, tags) in [
        (1, 0, Some("Access Link"), 2),
        (2, 1, Some("Access Link backup"), 2),
        (3, 2, None, 2),
        (4, 0, Some("Access Link"), 3),
        (5, 0, Some("Access Link"), 1),
    ] {
        let mut packet = arp::reply(frame, frame as f64, 20, 1);
        if tags >= 2 {
            packet.bytes.splice(12..12, [0x88, 0xa8, 0, 100]);
        }
        if tags == 3 {
            packet.bytes.splice(20..20, [0x81, 0, 0, 30]);
        }
        let length = packet.bytes.len() as u32;
        packet.length = length as u16;
        packet.capture = Some(CaptureMetadata {
            timestamp: Some(CaptureTimestamp { ticks: frame, resolution: TimestampResolution::Decimal(0), offset_seconds: 0 }),
            captured_length: length, wire_length: length, link_type: 1,
            section_id: 0, interface_id, interface_name: name.map(str::to_owned), comments: Vec::new(),
        });
        writer.write_packet(&packet).unwrap();
    }
    writer.flush().unwrap();

    let policy = "vlan.tag_stack_policy_violation";
    let observation = "vlan.tag_stack_observed";
    let manifest = root.join("policy.json");
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":[
        {"name":"default policy","capture":"mixed.pcapng","expect_snapshots":3,
         "expect_counts":{(policy):0,(observation):3},"opening_frames":{(observation):[1,2,3]}},
        {"name":"named access policy","capture":"mixed.pcapng","single_tag_interfaces":["Access Link"],"expect_snapshots":4,
         "expect_counts":{(policy):2,(observation):2},"opening_frames":{(policy):[1,4],(observation):[2,3]},
         "opening_evidence":[{"rule_id":policy,"opening_frame":1,"frames":[1]},
                             {"rule_id":policy,"opening_frame":4,"frames":[4]}]},
    ]}).to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    assert_eq!(serde_json::from_slice::<Value>(&output.stdout).unwrap()["passed"], 2);
}
