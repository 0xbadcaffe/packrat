use super::{
    CaptureMetadata, CaptureTimestamp, PcapNgWriter, TimestampResolution, json, run_suite,
};
use packrat_tui::net::parser::parse_ethernet;
use std::path::Path;

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
    let mut write = |host, flags, acknowledgement: u32| {
        frame += 1;
        let reply = flags != 0x02;
        let mut raw = super::support::tcp(frame, 100, flags, &[], reply).bytes;
        raw[if reply { 29 } else { 33 }] = host;
        raw[42..46].copy_from_slice(&acknowledgement.to_be_bytes());
        capture.write_packet(&parse_ethernet(&raw, frame, frame as f64 / 100.0)).unwrap();
    };
    write(21, 0x02, 0);
    write(21, 0x12, 101);
    write(21, 0x14, 102); // Wrong acknowledgement.
    write(22, 0x02, 0);
    write(22, 0x14, 101);
    for host in 23..=32 {
        write(host, 0x02, 0);
    }
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
    let frames = (1..=15).filter(|&frame| frame != 3).collect::<Vec<_>>();
    cases.push(json!({
        "name":"scoped-reply-evidence", "capture":capture, "expect_snapshots":1,
        "expect_counts":{(horizontal):1,(vertical):0}, "opening_frames":{(horizontal):[15]},
        "opening_evidence":[{"rule_id":horizontal,"opening_frame":15,"frames":frames}],
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
