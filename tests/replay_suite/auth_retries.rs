use super::{PcapNgWriter, json, run_suite};

#[path = "../support/smb_ntlm.rs"]
mod smb_ntlm;

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn ntlm_fanout_replay_distinguishes_rearmed_bursts_from_sustained_and_single_host_traffic() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let rule = "smb2.ntlm_authentication_fanout";
    let payload = smb_ntlm::smb2_ntlm_request(3);
    let mut cases = Vec::new();
    for (name, late, diverse, tagged_paths, openings) in [
        ("rearmed", 604, true, None, &[3_u64, 7][..]),
        ("sustained", 305, true, None, &[3][..]),
        ("one-target", 604, false, None, &[][..]),
        ("same-tag-type-different-priority", 604, true, Some(false), &[3, 7][..]),
        ("same-vlan-id-distinct-tag-types", 604, true, Some(true), &[][..]),
    ] {
        let file = format!("{name}.pcapng");
        let mut writer = PcapNgWriter::create(&root.join(&file)).unwrap();
        for (index, time) in [1, 3, 4, 302, late - 2, late - 1, late].into_iter().enumerate() {
            let frame = index as u64 + 1;
            let mut packet = super::support::tcp(frame, frame as u32 * 1024, 0x18, &payload, false);
            let target = if diverse { frame as u8 } else { 1 };
            packet.bytes[26..34].copy_from_slice(&[10, 0, 0, 9, 10, 0, 2, target]);
            packet.bytes[36..38].copy_from_slice(&445_u16.to_be_bytes());
            if let Some(split) = tagged_paths {
                let tpid = if split && frame % 3 == 2 { 0x88a8_u16 } else { 0x8100_u16 };
                let tci = if frame % 2 == 0 { 0xb014_u16 } else { 20_u16 };
                packet.bytes.splice(12..12, [tpid, tci].into_iter().flat_map(u16::to_be_bytes));
            }
            packet.timestamp = f64::from(time);
            writer.write_packet(&packet).unwrap();
        }
        writer.flush().unwrap();
        let mut case = json!({
            "name":name, "capture":file, "expect_snapshots":openings.len(),
            "expect_counts":{(rule):openings.len()},
        });
        if !openings.is_empty() {
            case["opening_frames"] = json!({(rule):openings});
            let evidence: Vec<_> = openings.iter().map(|&frame| json!({
                "rule_id":rule, "opening_frame":frame, "frames":[frame - 2, frame - 1, frame],
                "classification":{"severity":"MEDIUM","confidence":"correlated","revision":5},
            })).collect();
            case["opening_evidence"] = json!(evidence);
        }
        cases.push(case);
    }
    let manifest = root.join("ntlm-fanout.json");
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":cases}).to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn delayed_auth_retries_do_not_open_a_new_burst() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let capture = root.join("authentication.pcapng");
    let mut writer = PcapNgWriter::create(&capture).unwrap();
    let response = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
    let mut frame = 0;
    for (start, sequence_base) in [(1, 100), (41, 100), (51, 1000)] {
        for offset in 0..5 {
            frame += 1;
            let mut packet = super::support::tcp(frame, sequence_base + offset * 100, 0x18, response, true);
            packet.timestamp = f64::from(start + offset);
            writer.write_packet(&packet).unwrap();
        }
    }
    writer.flush().unwrap();
    let manifest = root.join("auth-retries.json");
    let rule = "http.unauthorized_burst";
    let labels = json!({
        "version":1,"strict":true,"cases":[{
            "name":"auth retries after the burst window and distinct later replies",
            "capture":"authentication.pcapng",
            "expect_snapshots":2,
            "expect_counts":{(rule):2},
            "opening_frames":{(rule):[5,15]},
            "opening_evidence":[
                {"rule_id":rule,"opening_frame":5,"frames":[1,2,3,4,5],
                 "classification":{"severity":"MEDIUM","confidence":"direct_observation","revision":16}},
                {"rule_id":rule,"opening_frame":15,"frames":[11,12,13,14,15],
                 "classification":{"severity":"MEDIUM","confidence":"direct_observation","revision":16}}
            ]
        }]
    });
    std::fs::write(&manifest, labels.to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn auth_replay_distinguishes_status_lines_from_body_text_at_segment_boundaries() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let request = b"GET /status HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let sample = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
    let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", sample.len());
    let rule = "http.unauthorized_burst";
    let mut cases = Vec::new();
    for (file, body) in [("status.pcapng", false), ("response-body.pcapng", true)] {
        let mut writer = PcapNgWriter::create(&root.join(file)).unwrap();
        let mut frame = 0;
        let mut write = |sequence, flags, payload, reverse| {
            frame += 1;
            writer.write_packet(&super::support::tcp(frame, sequence, flags, payload, reverse)).unwrap();
        };
        write(100, 0x02, &[], false);
        write(500, 0x12, &[], true);
        let mut server_seq = 501;
        for repeat in 0..5 {
            write(101 + repeat * request.len() as u32, 0x18, request, false);
            if body {
                write(server_seq, 0x18, header.as_bytes(), true);
                server_seq += header.len() as u32;
            }
            write(server_seq, 0x18, sample, true);
            if body { write(server_seq, 0x18, sample, true); }
            server_seq += sample.len() as u32;
        }
        writer.flush().unwrap();
        cases.push(if body {
            json!({"name":"status example in a 200 response body","capture":file,
                "expect_snapshots":0,"expect_counts":{(rule):0}})
        } else {
            json!({"name":"actual 401 responses","capture":file,
                "expect_snapshots":1,"expect_counts":{(rule):1},"opening_frames":{(rule):[12]},
                "opening_evidence":[{"rule_id":rule,"opening_frame":12,"frames":(3..=12).collect::<Vec<_>>(),
                    "classification":{"severity":"MEDIUM","confidence":"direct_observation","revision":16}}]})
        });
    }
    let manifest = root.join("auth-status-boundaries.json");
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":cases}).to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn auth_replay_measures_ordered_gap_filled_and_unavailable_response_evidence() {
    use super::support::{AuthResponseDelivery::*, write_coalesced_auth_capture};
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let rule = "http.unauthorized_burst";
    let cases: Vec<_> = [
        ("ordered", Ordered),
        ("gap-filled", GapFilled),
        ("prefix-missing", PrefixMissing),
        ("same-tag-path", TaggedGapFilled),
        ("split-tag-path", SplitTagTypes),
    ].into_iter().map(|(name, delivery)| {
        let file = format!("{name}.pcapng");
        if let Some(trigger) = write_coalesced_auth_capture(&root.join(&file), delivery) {
            json!({"name":name,"capture":file,"expect_snapshots":1,
                "expect_counts":{(rule):1},"opening_frames":{(rule):[trigger]},
                "opening_evidence":[{"rule_id":rule,"opening_frame":trigger,"frames":(3..=trigger).collect::<Vec<_>>(),
                    "classification":{"severity":"MEDIUM","confidence":"direct_observation"}}]})
        } else {
            json!({"name":name,"capture":file,"expect_snapshots":0,"expect_counts":{(rule):0}})
        }
    }).collect();
    let manifest = root.join("auth-stream-coverage.json");
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":cases}).to_string()).unwrap();
    let baseline = std::env::var("PACKRAT_REPLAY_BASELINE_ANALYZER").ok();
    let output = super::run_suite_with_baseline(&manifest, baseline.as_deref());
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    if baseline.is_some() {
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }
}
