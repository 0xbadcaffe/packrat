use super::{PcapNgWriter, json, run_suite_with_baseline, support};
use packrat_tui::net::parser::parse_ethernet;
use std::path::Path;

fn vlan_tag(raw: &mut Vec<u8>, provider: bool, marked: bool) {
    let tpid = if provider { 0x88a8_u16 } else { 0x8100_u16 };
    let tci = if marked { 20 | 0xb000_u16 } else { 20_u16 };
    raw.splice(12..12, [tpid, tci].into_iter().flat_map(u16::to_be_bytes));
}

fn write_capture(path: &Path, split_tag_types: bool, vertical: bool) {
    let mut writer = PcapNgWriter::create(path).unwrap();
    for frame in 1..=14_u64 {
        if split_tag_types && frame > 12 {
            break;
        }
        let reply = frame > 12;
        let sample = frame.min(12);
        let port = if vertical {
            8_000 + sample as u16
        } else {
            443_u16
        };
        let host = if vertical { 21 } else { 20 + sample as u8 };
        let flags = if reply { 0x12 } else { 0x02 };
        let mut raw = support::tcp(frame, 100, flags, &[], reply).bytes;
        raw[if reply { 29 } else { 33 }] = host;
        let port_offset = if reply { 34 } else { 36 };
        raw[port_offset..port_offset + 2].copy_from_slice(&port.to_be_bytes());
        if reply {
            raw[42..46].copy_from_slice(&101_u32.to_be_bytes());
        }
        vlan_tag(
            &mut raw,
            (split_tag_types && frame > 6) || frame == 13,
            frame % 2 == 0 && frame != 14,
        );
        let packet = parse_ethernet(&raw, frame, frame as f64 / 100.0);
        writer.write_packet(&packet).unwrap();
    }
    writer.flush().unwrap();
}

fn write_burst(path: &Path, split: bool, echo: bool, threshold: u64) {
    let mut writer = PcapNgWriter::create(path).unwrap();
    for frame in 1..=threshold {
        let mut raw = support::tcp(frame, 100, 0x02, &[], false).bytes;
        if echo {
            raw[33] = 20 + frame as u8;
            raw[23] = 1;
            raw[16..18].copy_from_slice(&28_u16.to_be_bytes());
            raw.truncate(34);
            raw.extend([8, 0, 0, 0, 0, 1, 0, 1]);
        } else {
            raw[29] = 20 + frame as u8;
        }
        vlan_tag(&mut raw, split && frame > threshold / 2, frame % 2 == 0);
        let packet = parse_ethernet(&raw, frame, frame as f64 / 200.0);
        writer.write_packet(&packet).unwrap();
    }
    writer.flush().unwrap();
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn scans_do_not_merge_equal_vlan_ids_across_different_tag_types() {
    let root = tempfile::tempdir().unwrap();
    let mut cases = Vec::new();
    for (file, split, vertical) in [
        ("horizontal-split.pcapng", true, false),
        ("vertical-split.pcapng", true, true),
        ("horizontal-marked.pcapng", false, false),
        ("vertical-marked.pcapng", false, true),
    ] {
        write_capture(&root.path().join(file), split, vertical);
        let rule = if vertical {
            "scan.vertical"
        } else {
            "scan.horizontal"
        };
        let mut case = json!({"name":file,"capture":file,"expect_counts":{(rule):usize::from(!split)},
            "expect_snapshots":if split { 0 } else { 2 }});
        if !split {
            case["opening_frames"] = json!({(rule):[12]});
            case["opening_evidence"] = json!([{"rule_id":rule,"opening_frame":12,
                "frames":(1..=12).collect::<Vec<_>>()}]);
        }
        cases.push(case);
    }
    for (file, split, echo, threshold, rule) in [
        ("echo-split.pcapng", true, true, 12, "icmp.address_sweep"),
        ("echo-marked.pcapng", false, true, 12, "icmp.address_sweep"),
        (
            "syn-split.pcapng",
            true,
            false,
            100,
            "tcp.syn_arrival_spike",
        ),
        (
            "syn-marked.pcapng",
            false,
            false,
            100,
            "tcp.syn_arrival_spike",
        ),
    ] {
        write_burst(&root.path().join(file), split, echo, threshold);
        let mut case = json!({"name":file,"capture":file,"expect_counts":{(rule):usize::from(!split)},
            "expect_snapshots":usize::from(!split)});
        if !split {
            case["opening_frames"] = json!({(rule):[threshold]});
            case["opening_evidence"] = json!([{"rule_id":rule,"opening_frame":threshold,
                "frames":(1..=threshold).collect::<Vec<_>>()}]);
        }
        cases.push(case);
    }
    let manifest = root.path().join("suite.json");
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
        for case in report["cases"].as_array().unwrap() {
            if case["name"].as_str().unwrap().ends_with("-split.pcapng") {
                assert_eq!(case["delta"]["count_surplus"], -1);
            }
        }
    }
    for file in ["horizontal-marked.pcapng", "vertical-marked.pcapng"] {
        let capture = std::process::Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
            .arg("--alerts-only")
            .arg(root.path().join(file))
            .output()
            .unwrap();
        assert!(capture.status.success());
        let output = String::from_utf8(capture.stdout).unwrap();
        let update: serde_json::Value =
            serde_json::from_str(output.lines().nth(1).unwrap()).unwrap();
        assert_eq!(update["opening"], false);
        let frames = update["alert"]["packet_refs"].as_array().unwrap();
        assert!(frames.contains(&json!(14)));
        assert!(!frames.contains(&json!(13)));
    }
}
