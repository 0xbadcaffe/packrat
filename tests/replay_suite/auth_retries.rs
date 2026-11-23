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
                {"rule_id":rule,"opening_frame":5,"frames":[1,2,3,4,5]},
                {"rule_id":rule,"opening_frame":15,"frames":[11,12,13,14,15]}
            ]
        }]
    });
    std::fs::write(&manifest, labels.to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
}
