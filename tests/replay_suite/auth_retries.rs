use super::{PcapNgWriter, json, run_suite};

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
                 "classification":{"severity":"MEDIUM","confidence":"direct_observation","revision":14}},
                {"rule_id":rule,"opening_frame":15,"frames":[11,12,13,14,15],
                 "classification":{"severity":"MEDIUM","confidence":"direct_observation","revision":14}}
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
                    "classification":{"severity":"MEDIUM","confidence":"direct_observation","revision":14}}]})
        });
    }
    let manifest = root.join("auth-status-boundaries.json");
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":cases}).to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
}
