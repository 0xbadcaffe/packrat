use super::{PcapNgWriter, json, run_suite_with_baseline, support};

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn reset_replay_separates_reopened_connections_from_unexplained_payload() {
    let root = tempfile::tempdir().unwrap();
    let rule = "tcp.payload_after_observed_reset";
    for (name, reopening) in [("reopening", true), ("post-reset-data", false)] {
        let mut writer = PcapNgWriter::create(&root.path().join(format!("{name}.pcapng"))).unwrap();
        for packet in [
            support::tcp(1, 100, 0x02, b"", false),
            support::tcp(2, 110, 0x04, b"", false),
        ] {
            writer.write_packet(&packet).unwrap();
        }
        if reopening {
            writer
                .write_packet(&support::tcp(3, 100, 0x02, b"early data", false))
                .unwrap();
            writer
                .write_packet(&support::tcp(4, 111, 0x18, b"new connection data", false))
                .unwrap();
        } else {
            writer
                .write_packet(&support::tcp(3, 111, 0x18, b"later data", false))
                .unwrap();
        }
        writer.flush().unwrap();
    }
    let mut writer = PcapNgWriter::create(&root.path().join("separate-tag-paths.pcapng")).unwrap();
    for (frame, sequence, flags, payload, tpid) in [
        (1, 100, 0x02, &b""[..], 0x8100_u16),
        (2, 110, 0x04, &b""[..], 0x8100),
        (3, 111, 0x18, &b"independent path"[..], 0x88a8),
    ] {
        let mut packet = support::tcp(frame, sequence, flags, payload, false);
        packet.bytes.splice(12..12, [tpid, 20].into_iter().flat_map(u16::to_be_bytes));
        writer.write_packet(&packet).unwrap();
    }
    writer.flush().unwrap();
    let manifest = root.path().join("reset-reopen.json");
    let labels = json!({"version":1,"strict":true,"cases":[
        {"name":"observed reopening","capture":"reopening.pcapng","expect_counts":{(rule):0},"expect_snapshots":0},
        {"name":"reset on a separate tag path","capture":"separate-tag-paths.pcapng","expect_counts":{(rule):0},"expect_snapshots":0},
        {"name":"payload without an observed reopen","capture":"post-reset-data.pcapng",
         "expect_counts":{(rule):1},"expect_snapshots":1,"opening_frames":{(rule):[3]},
         "opening_evidence":[{"rule_id":rule,"opening_frame":3,"frames":[2,3],
            "classification":{"severity":"MEDIUM","confidence":"heuristic","revision":11}}]}
    ]});
    std::fs::write(&manifest, labels.to_string()).unwrap();
    let baseline = std::env::var("PACKRAT_REPLAY_BASELINE_ANALYZER").ok();
    let output = run_suite_with_baseline(&manifest, baseline.as_deref());
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 3);
    if baseline.is_some() {
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }
}
