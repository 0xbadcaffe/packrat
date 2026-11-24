use super::{
    CaptureMetadata, CaptureTimestamp, PcapNgWriter, TimestampResolution, json, run_suite,
};
use packrat_tui::net::parser::parse_ethernet;
use std::path::Path;

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn tcp_header_replay_distinguishes_proven_invalid_offsets_from_truncation() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let rule = "tcp.invalid_header";
    let mut cases = Vec::new();
    for (name, offset, captured_tcp, expected) in [
        ("ipv6-valid-short-capture", 0x60, 13, 0),
        ("ipv6-offset-not-captured", 0xb0, 12, 0),
        ("ipv6-observed-invalid-offset", 0xb0, 13, 1),
    ] {
        let file = format!("{name}.pcapng");
        let tcp = super::support::tcp(1, 100, 0x18, &[0; 20], false);
        let mut bytes = vec![0; 54];
        bytes[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        bytes[14] = 0x60;
        bytes[18..20].copy_from_slice(&48_u16.to_be_bytes());
        bytes[20] = 60;
        bytes[21] = 64;
        for (start, address) in [(22, "2001:db8::1"), (38, "2001:db8::2")] {
            bytes[start..start + 16].copy_from_slice(&address.parse::<std::net::Ipv6Addr>().unwrap().octets());
        }
        bytes.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&tcp.bytes[34..]);
        bytes[74] = offset;
        let wire_length = bytes.len() as u32;
        bytes.truncate(62 + captured_tcp);
        let mut packet = parse_ethernet(&bytes, 1, 1.0);
        packet.capture = Some(CaptureMetadata {
            timestamp: Some(CaptureTimestamp { ticks: 1, resolution: TimestampResolution::Decimal(0), offset_seconds: 0 }),
            captured_length: bytes.len() as u32, wire_length, link_type: 1, interface_id: 0,
            section_id: 0, interface_name: None, comments: Vec::new(),
        });
        let mut writer = PcapNgWriter::create(&root.join(&file)).unwrap();
        writer.write_packet(&packet).unwrap();
        writer.flush().unwrap();
        let mut case = json!({
            "name":name, "capture":file, "allow_truncated":true,
            "expect_counts":{(rule):expected}, "expect_snapshots":expected,
        });
        if expected == 1 {
            case["opening_frames"] = json!({(rule):[1]});
            case["opening_evidence"] = json!([{
                "rule_id":rule,"opening_frame":1,"frames":[1],
                "classification":{"severity":"HIGH","confidence":"direct_observation","revision":3},
            }]);
        }
        cases.push(case);
    }
    let manifest = root.join("tcp-framing.json");
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":cases}).to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 3);
    for case in report["cases"].as_array().unwrap() {
        assert_eq!(case["summary"]["truncated_frames"], 1);
    }
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn admin_fanout_replay_requires_a_timely_syn_or_its_exact_retry() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let rule = "tcp.admin_service_response_fanout";
    let mut cases = Vec::new();
    for (name, retry_host, final_time, expected) in [
        ("valid-retry", 8, 17.0, 1),
        ("unrelated-retry", 9, 17.0, 0),
        ("reply-before-syn", 8, 0.5, 0),
    ] {
        let file = format!("{name}.pcapng");
        let mut capture = PcapNgWriter::create(&root.join(&file)).unwrap();
        let mut frame = 0;
        let mut write = |host, at, reply| {
            frame += 1;
            let flags = if reply { 0x12 } else { 0x02 };
            let mut raw = super::support::tcp(frame, 100, flags, &[], reply).bytes;
            let (src, dst) = if reply { ([10, 0, 1, host], [10, 0, 0, 9]) }
                else { ([10, 0, 0, 9], [10, 0, 1, host]) };
            raw[26..30].copy_from_slice(&src);
            raw[30..34].copy_from_slice(&dst);
            let port = if reply { 34 } else { 36 };
            raw[port..port + 2].copy_from_slice(&445_u16.to_be_bytes());
            if reply { raw[42..46].copy_from_slice(&101_u32.to_be_bytes()); }
            capture.write_packet(&parse_ethernet(&raw, frame, at)).unwrap();
        };
        write(8, 1.0, false);
        for host in 1..=7_u8 {
            write(host, 2.0 + f64::from(host) / 10.0, false);
            write(host, 2.05 + f64::from(host) / 10.0, true);
        }
        write(retry_host, 10.0, false);
        write(8, final_time, true);
        capture.flush().unwrap();
        let mut case = json!({
            "name":name, "capture":file, "expect_counts":{(rule):expected},
            "expect_snapshots":expected,
        });
        if expected == 1 {
            case["opening_frames"] = json!({(rule):[17]});
            case["opening_evidence"] = json!([{
                "rule_id":rule, "opening_frame":17, "frames":(2..=17).collect::<Vec<_>>(),
                "classification":{"severity":"MEDIUM","confidence":"correlated","revision":3},
            }]);
        }
        cases.push(case);
    }
    let manifest = root.join("admin-fanout-retries.json");
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":cases}).to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

fn write_observations(path: &Path, vary_host: bool, vary_port: bool, partial: bool) {
    let mut capture = PcapNgWriter::create(path).unwrap();
    for no in 1..=12_u64 {
        let mut raw = super::support::tcp(no, no as u32, 0x02, &[1, 1, 0, 0], false).bytes;
        raw[46] = 0x60;
        if vary_host {
            raw[33] = 16 + no as u8;
        }
        if vary_port {
            raw[36..38].copy_from_slice(&(8000 + no as u16).to_be_bytes());
        }
        let wire_length = raw.len() as u32;
        if partial {
            raw.truncate(54);
        }
        let mut packet = parse_ethernet(&raw, no, no as f64);
        packet.capture = Some(CaptureMetadata {
            captured_length: raw.len() as u32,
            wire_length,
            link_type: 1,
            section_id: 0,
            interface_id: 0,
            interface_name: None,
            timestamp: Some(CaptureTimestamp {
                ticks: no * 1_000_000,
                resolution: TimestampResolution::Decimal(6),
                offset_seconds: 0,
            }),
            comments: Vec::new(),
        });
        capture.write_packet(&packet).unwrap();
    }
    capture.flush().unwrap();
}

fn write_scan_with_replies(path: &Path) {
    let mut capture = PcapNgWriter::create(path).unwrap();
    let mut frame = 0;
    let mut write = |host, flags, acknowledgement: u32, sequence: u32| {
        frame += 1;
        let reply = matches!(flags, 0x12 | 0x14);
        let payload: &[u8] = if flags == 0x18 { b"application data" } else { &[] };
        let mut raw = super::support::tcp(frame, sequence, flags, payload, reply).bytes;
        raw[if reply { 29 } else { 33 }] = host;
        raw[42..46].copy_from_slice(&acknowledgement.to_be_bytes());
        capture.write_packet(&parse_ethernet(&raw, frame, frame as f64 / 100.0)).unwrap();
    };
    write(21, 0x02, 0, 100);
    write(21, 0x12, 101, 100);
    write(21, 0x12, 102, 100); // Wrong acknowledgement.
    write(22, 0x02, 0, 100);
    write(22, 0x14, 101, 100);
    write(21, 0x02, 0, 100); // Identical retry must not replace the matched pair.
    write(21, 0x18, 101, 101); // The matching third leg also carries data.
    for host in 23..=32 {
        write(host, 0x02, 0, 100);
    }
    write(32, 0x02, 0, 500); // New attempt to the same target was not part of the alert.
    write(32, 0x12, 501, 700);
    write(32, 0x12, 101, 100); // Retain the late SYN-ACK for the opening probe.
    write(32, 0x12, 101, 100); // The retransmission does not update the alert.
    write(32, 0x18, 101, 101); // Retain the matching final ACK with data.
    write(33, 0x02, 0, 100);
    write(33, 0x12, 101, 100); // This probe was never part of the alert.
    capture.flush().unwrap();
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn scan_replay_distinguishes_complete_distinct_observations_from_repeats_and_truncation() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let horizontal = "scan.horizontal";
    let vertical = "scan.vertical";
    let mut cases: Vec<_> = [
        ("same-destination-and-port", false, false, false, None),
        ("distinct-hosts-truncated", true, false, true, None),
        ("distinct-ports-truncated", false, true, true, None),
        (
            "distinct-hosts-complete",
            true,
            false,
            false,
            Some(horizontal),
        ),
        (
            "distinct-ports-complete",
            false,
            true,
            false,
            Some(vertical),
        ),
    ]
    .into_iter()
    .map(|(name, host, port, partial, expected)| {
        let capture = format!("{name}.pcapng");
        write_observations(&root.join(&capture), host, port, partial);
        let mut case = json!({
            "name":name, "capture":capture, "allow_truncated":partial,
            "expect_snapshots":usize::from(expected.is_some()),
            "expect_counts":{(horizontal):usize::from(expected==Some(horizontal)),
                             (vertical):usize::from(expected==Some(vertical))}
        });
        if let Some(rule) = expected {
            case["opening_frames"] = json!({(rule):[12]});
            case["opening_evidence"] =
                json!([{"rule_id":rule,"opening_frame":12,"frames":(1..=12).collect::<Vec<_>>()}]);
        }
        case
    })
    .collect();
    let capture = "fan-out-with-replies.pcapng";
    write_scan_with_replies(&root.join(capture));
    let frames = (1..=17).filter(|frame| !matches!(frame, 3 | 6)).collect::<Vec<_>>();
    cases.push(json!({
        "name":"scoped-reply-evidence", "capture":capture, "expect_snapshots":3,
        "expect_counts":{(horizontal):1,(vertical):0}, "opening_frames":{(horizontal):[17]},
        "opening_evidence":[{"rule_id":horizontal,"opening_frame":17,"frames":frames}],
    }));
    let separate = "separate-bursts.pcapng";
    let mut writer = PcapNgWriter::create(&root.join(separate)).unwrap();
    for frame in 1..=24 {
        let mut raw = super::support::tcp(frame, frame as u32, 0x02, &[], false).bytes;
        raw[33] = 16 + frame as u8;
        let seconds = frame as f64 / 4.0 + if frame > 12 { 26.0 } else { 0.0 };
        writer.write_packet(&parse_ethernet(&raw, frame, seconds)).unwrap();
    }
    writer.flush().unwrap();
    cases.push(json!({
        "name":"fan-out bursts separated by an idle gap","capture":separate,"expect_snapshots":2,
        "expect_counts":{(horizontal):2,(vertical):0},"opening_frames":{(horizontal):[12,24]},
        "opening_evidence":[
            {"rule_id":horizontal,"opening_frame":12,"frames":(1..=12).collect::<Vec<_>>()},
            {"rule_id":horizontal,"opening_frame":24,"frames":(13..=24).collect::<Vec<_>>()}
        ]
    }));
    let manifest = root.join("scan-suite.json");
    std::fs::write(
        &manifest,
        json!({"version":1,"strict":true,"cases":cases}).to_string(),
    )
    .unwrap();
    let output = run_suite(&manifest);
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
        .arg("--alerts-only").arg(root.join(capture)).output().unwrap();
    assert!(output.status.success());
    let records: Vec<_> = String::from_utf8(output.stdout).unwrap().lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|record| record["type"] == "alert").collect();
    assert_eq!(records.iter().map(|record| record["opening"].as_bool()).collect::<Vec<_>>(),
               [Some(true), Some(false), Some(false)]);
    let alerts: Vec<_> = records.iter().map(|record| &record["alert"]).collect();
    assert!(alerts[0]["detail"].as_str().unwrap().contains("over 0.160s within a 15s observation window"));
    assert_eq!(alerts[2]["provenance"]["revision"], 14);
    for field in ["id", "hit_count", "packet_no", "flow", "first_seen", "last_seen", "detail"] {
        assert_eq!(alerts[0][field], alerts[2][field], "{field}");
    }
    let mut evidence = alerts[0]["packet_refs"].as_array().unwrap().clone();
    evidence.extend([json!(20), json!(22)]);
    assert_eq!(alerts[2]["packet_refs"], json!(evidence));
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn syn_spike_replay_counts_new_attempts_but_not_late_retries() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let path = root.join("syn-retries.pcapng");
    let mut capture = PcapNgWriter::create(&path).unwrap();
    for (ticks, sequences) in [(1000, 0..50), (2100, 50..100), (3200, 0..100), (3200, 100..200)] {
        for sequence in sequences {
            let mut packet = super::support::tcp(0, sequence, 0x02, &[], false);
            let length = packet.bytes.len() as u32;
            packet.capture = Some(CaptureMetadata {
                captured_length: length, wire_length: length, link_type: 1,
                section_id: 0, interface_id: 0, interface_name: None, comments: Vec::new(),
                timestamp: Some(CaptureTimestamp {
                    ticks, resolution: TimestampResolution::Decimal(3), offset_seconds: 0,
                }),
            });
            capture.write_packet(&packet).unwrap();
        }
    }
    capture.flush().unwrap();
    let manifest = root.join("syn-suite.json");
    let rule = "tcp.syn_arrival_spike";
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":[{
        "name":"late-syn-retries","capture":"syn-retries.pcapng","expect_snapshots":1,
        "expect_counts":{(rule):1},"opening_frames":{(rule):[300]},
        "opening_evidence":[{"rule_id":rule,"opening_frame":300,"frames":(201..=300).collect::<Vec<_>>()}]
    }]}).to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
