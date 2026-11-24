use super::{PcapNgWriter, json, run_suite_with_baseline, support};
use packrat_tui::net::parser::parse_ethernet;
use std::path::Path;

fn write_handshakes(path: &Path, ipv6: bool) {
    let mut capture = PcapNgWriter::create(path).unwrap();
    let mut number = 0;
    let mut write = |host: u8, flags, seq, ack: u32, payload: &[u8]| {
        number += 1;
        let reply = flags == 0x12;
        let mut raw = support::tcp(number, seq, flags, payload, reply).bytes;
        raw[if reply { 29 } else { 33 }] = host;
        raw[42..46].copy_from_slice(&ack.to_be_bytes());
        if ipv6 {
            let mut ip = [0; 40];
            ip[0] = 0x60;
            ip[4..6].copy_from_slice(&((raw.len() - 34) as u16).to_be_bytes());
            ip[6..8].copy_from_slice(&[6, 64]);
            for start in [8, 24] {
                ip[start..start + 4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
            }
            ip[20..24].copy_from_slice(&raw[26..30]);
            ip[36..40].copy_from_slice(&raw[30..34]);
            raw[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
            raw.splice(14..34, ip);
        }
        let packet = parse_ethernet(&raw, number, number as f64 / 100.0);
        capture.write_packet(&packet).unwrap();
    };
    write(21, 0x02, u32::MAX - 1, 0, b"abc");
    write(21, 0x12, 500, 3, b"hi"); // Beyond the observed client data.
    write(21, 0x12, 500, 2, b"hi");
    write(21, 0x10, 0, 503, b""); // Not the server's acknowledged client sequence.
    write(21, 0x10, 2, 504, b""); // Beyond the observed server data.
    write(21, 0x10, 2, 503, b"");
    for host in 22..=32 {
        write(host, 0x02, 100, 0, b"abcde");
    }
    write(32, 0x02, 102, 0, b"");
    write(32, 0x12, 500, 103, b""); // Fits the old and the new attempt.
    write(32, 0x12, 500, 106, b""); // Fits only the cited attempt.
    capture.flush().unwrap();
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn scan_replay_links_payload_handshakes_without_citing_overlapping_candidates() {
    let work = tempfile::tempdir().unwrap();
    let files = ["handshakes-v4.pcapng", "handshakes-v6.pcapng"];
    let manifest = work.path().join("suite.json");
    let rule = "scan.horizontal";
    let expected: Vec<_> = [1, 3, 6].into_iter().chain(7..=17).collect();
    let cases: Vec<_> = files
        .iter()
        .enumerate()
        .map(|(index, file)| {
            write_handshakes(&work.path().join(file), index == 1);
            json!({
                "name":file,"capture":file,"expect_counts":{(rule):1},
                "expect_snapshots":2,"opening_frames":{(rule):[17]},
                "opening_evidence":[{"rule_id":rule,"opening_frame":17,"frames":expected,
                    "classification":{"severity":"HIGH","confidence":"heuristic","revision":17}}]
            })
        })
        .collect();
    std::fs::write(
        &manifest,
        json!({"version":1,"strict":true,"cases":cases}).to_string(),
    )
    .unwrap();
    let baseline = std::env::var("PACKRAT_REPLAY_BASELINE_ANALYZER").ok();
    let output = run_suite_with_baseline(&manifest, baseline.as_deref());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    if baseline.is_some() {
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["comparable"], 2);
        for case in report["cases"].as_array().unwrap() {
            assert_eq!(case["delta"]["evidence_frame_mismatches"], -1);
            assert_eq!(case["delta"]["snapshot_deficit"], -1);
        }
    }
    for file in files {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
            .arg("--alerts-only")
            .arg(work.path().join(file))
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        let update: serde_json::Value =
            serde_json::from_str(stdout.lines().nth(1).unwrap()).unwrap();
        assert_eq!(update["opening"], false);
        let frames = update["alert"]["packet_refs"].as_array().unwrap();
        assert!(frames.contains(&json!(20)));
        assert!(!frames.contains(&json!(19)));
    }
}
