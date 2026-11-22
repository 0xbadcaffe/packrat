use super::{PcapNgWriter, Value, json, run_suite};

#[path = "../support/tls_selection.rs"]
mod wire;

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn tls_replay_requires_complete_tcp_bytes_and_retains_contributing_frames() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let legacy = wire::server_hello(0x0302, 0xc011, &[]);
    let modern = wire::server_hello(0x0303, 0x1301, &[0, 43, 0, 2, 3, 4]);
    let rules = ["tls.tls11_selected", "tls.rc4_selected"];
    let mut cases = Vec::new();
    for (name, hello, fill_gap, expected) in [
        ("out-of-order-legacy-hello", &legacy, true, 1),
        ("incomplete-legacy-hello", &legacy, false, 0),
        ("modern-hello", &modern, true, 0),
    ] {
        let capture = format!("{name}.pcapng");
        let mut writer = PcapNgWriter::create(&root.join(&capture)).unwrap();
        for (no, sequence, flags, payload) in [
            (1, 100, 0x12, &[][..]),
            (2, 101, 0x18, &hello[..7]),
            (3, 120, 0x18, &hello[19..]),
            (4, 120, 0x18, &hello[19..]),
            (5, 108, 0x18, &hello[7..19]),
        ] {
            if no != 5 || fill_gap {
                writer
                    .write_packet(&wire::tls_segment(no, sequence, flags, payload))
                    .unwrap();
            }
        }
        writer.flush().unwrap();
        let mut case = json!({
            "name": name, "capture": capture, "expect_snapshots": expected * 2,
            "expect_counts": {(rules[0]):expected,(rules[1]):expected},
        });
        if expected == 1 {
            case["opening_frames"] = json!({(rules[0]):[5], (rules[1]):[5]});
            case["opening_evidence"] = json!(
                rules.map(|rule| { json!({"rule_id":rule,"opening_frame":5,"frames":[2,3,5]}) })
            );
        }
        cases.push(case);
    }
    let manifest = root.join("tls.json");
    std::fs::write(
        &manifest,
        json!({"version":1,"strict":true,"cases":cases}).to_string(),
    )
    .unwrap();
    let output = run_suite(&manifest);
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 3);
}
