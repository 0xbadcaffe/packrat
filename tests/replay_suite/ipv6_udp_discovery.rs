use super::{PcapNgWriter, json, run_suite_with_baseline};
use packrat_tui::net::parser::parse_ethernet;

fn frame(target: u8, port: u16) -> [u8; 62] {
    let mut raw = [0; 62];
    raw[0..6].copy_from_slice(&[2, 0, 0, 0, 0, target]);
    raw[6..12].copy_from_slice(&[2, 0, 0, 0, 1, 0]);
    raw[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
    raw[14] = 0x60;
    raw[18..22].copy_from_slice(&[0, 8, 17, 64]);
    raw[22..26].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    raw[37] = 1;
    raw[38..42].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    raw[53] = target + 1;
    raw[54..56].copy_from_slice(&40_000_u16.to_be_bytes());
    raw[56..58].copy_from_slice(&port.to_be_bytes());
    raw[58..60].copy_from_slice(&8_u16.to_be_bytes());
    let sum = raw[22..]
        .chunks_exact(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum::<u32>()
        + 8
        + 17;
    let folded = (sum & 0xffff) + (sum >> 16);
    let checksum = !(((folded & 0xffff) + (folded >> 16)) as u16);
    raw[60..62].copy_from_slice(&(if checksum == 0 { u16::MAX } else { checksum }).to_be_bytes());
    raw
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn ipv6_udp_replay_excludes_zero_destination_port_from_scan_evidence() {
    let scratch = tempfile::tempdir().unwrap();
    let horizontal = "scan.horizontal";
    let vertical = "scan.vertical";
    let mut cases = Vec::new();
    for (name, one_host, allow_zero, rule) in [
        ("zero-port-many-targets", false, true, None),
        ("zero-port-at-threshold", true, true, None),
        ("nonzero-port-many-targets", false, false, Some(horizontal)),
        ("nonzero-ports-one-target", true, false, Some(vertical)),
    ] {
        let filename = format!("{name}.pcapng");
        let mut capture = PcapNgWriter::create(&scratch.path().join(&filename)).unwrap();
        for number in 1..=12_u8 {
            let target = if one_host { 1 } else { number };
            let port = match (one_host, allow_zero, number) {
                (false, true, _) | (true, true, 12) => 0,
                (false, false, _) => 443,
                (true, _, _) => 8000 + u16::from(number),
            };
            let packet = parse_ethernet(
                &frame(target, port),
                number.into(),
                f64::from(number) / 10.0,
            );
            capture.write_packet(&packet).unwrap();
        }
        capture.flush().unwrap();
        let mut case = json!({
            "name":name, "capture":filename, "expect_snapshots":usize::from(rule.is_some()),
            "expect_counts":{(horizontal):usize::from(rule == Some(horizontal)),
                             (vertical):usize::from(rule == Some(vertical))},
        });
        if let Some(rule) = rule {
            case["opening_frames"] = json!({(rule):[12]});
            case["opening_evidence"] =
                json!([{"rule_id":rule,"opening_frame":12,"frames":(1..=12).collect::<Vec<_>>()}]);
        }
        cases.push(case);
    }
    let manifest = scratch.path().join("ipv6-udp.json");
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
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 4);
    if baseline.is_some() {
        assert_eq!(report["comparable"], 4);
        for index in 0..2 {
            assert_eq!(report["cases"][index]["baseline"]["verdict"], "failed");
            assert_eq!(report["cases"][index]["delta"]["count_surplus"], -1);
        }
        for index in 2..4 {
            assert_eq!(report["cases"][index]["baseline"]["verdict"], "passed");
            assert_eq!(report["cases"][index]["delta"]["alerts_opened"], 0);
        }
    }
}
