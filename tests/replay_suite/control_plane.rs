use super::{
    CaptureMetadata, CaptureTimestamp, PcapNgWriter, TimestampResolution, Value, json, run_suite,
};
use packrat_tui::net::parser::parse_ethernet;

const ROUTER: [u8; 6] = [2, 0, 0, 0, 0, 1];

fn ethernet(destination: [u8; 6], vlan: u16, kind: u16) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend(destination);
    frame.extend(ROUTER);
    frame.extend(0x8100_u16.to_be_bytes());
    frame.extend(vlan.to_be_bytes());
    frame.extend(kind.to_be_bytes());
    frame
}

fn router_solicitation(vlan: u16, hop_limit: u8) -> Vec<u8> {
    let mut frame = ethernet([0x33, 0x33, 0, 0, 0, 2], vlan, 0x86dd);
    frame.extend([0x60, 0, 0, 0, 0, 8, 58, hop_limit]);
    for address in ["fe80::1", "ff02::2"] {
        frame.extend(address.parse::<std::net::Ipv6Addr>().unwrap().octets());
    }
    frame.extend([133, 0, 0x7d, 0x36, 0, 0, 0, 0]);
    frame
}

fn router_advertisement(vlan: u16, host: u8) -> Vec<u8> {
    let mut frame = ethernet([0x33, 0x33, 0, 0, 0, 1], vlan, 0x86dd);
    frame[11] = host;
    frame.extend([0x60, 0, 0, 0, 0, 16, 58, 255]);
    for address in ["fe80::1", "ff02::1"] {
        frame.extend(address.parse::<std::net::Ipv6Addr>().unwrap().octets());
    }
    frame.extend([134, 0, 0x7b, 0xf3, 0, 0, 0, 60, 0, 0, 0, 0, 0, 0, 0, 0]);
    frame
}

fn configuration_bpdu(vlan: u16, flags: u8) -> Vec<u8> {
    let mut frame = ethernet([1, 0x80, 0xc2, 0, 0, 0], vlan, 38);
    frame.extend([0x42, 0x42, 3, 0, 0, 0, 0, flags]);
    frame.extend([0x80, 0]);
    frame.extend(ROUTER);
    frame.extend([0; 4]); // Root path cost.
    frame.extend([0x80, 0]);
    frame.extend(ROUTER);
    frame.extend([0x80, 1, 0, 0, 20, 0, 2, 0, 15, 0]);
    frame
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn default_router_link_replay_keeps_both_frames_on_one_vlan() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let rule = "ipv6.ra_router_link_change";
    let mut cases = Vec::new();
    for (name, observations, openings, snapshots) in [
        ("same-vlan", &[(10, 1), (10, 2)][..], vec![2], 1),
        ("other-vlan", &[(10, 1), (20, 2)][..], vec![], 0),
        ("same-pair", &[(10, 1), (10, 2), (10, 1), (10, 2)][..], vec![2], 3),
    ] {
        let capture = format!("{name}.pcapng");
        let mut writer = PcapNgWriter::create(&root.join(&capture)).unwrap();
        for (index, &(vlan, host)) in observations.iter().enumerate() {
            let no = index as u64 + 1;
            let frame = router_advertisement(vlan, host);
            writer.write_packet(&parse_ethernet(&frame, no, no as f64)).unwrap();
        }
        writer.flush().unwrap();
        let mut case = json!({"name":name,"capture":capture,"expect_counts":{(rule):openings.len()},
            "expect_snapshots":snapshots});
        if !openings.is_empty() {
            case["opening_frames"] = json!({(rule):openings});
            case["opening_evidence"] = json!([{"rule_id":rule,"opening_frame":2,"frames":[1,2]}]);
        }
        cases.push(case);
    }
    let manifest = root.join("router-link.json");
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":cases}).to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 3);
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn router_advertisement_burst_replay_excludes_bad_checksums_from_evidence() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let rule = "ipv6.ra_rate_burst";
    let cases: Vec<_> = [("below-threshold", 20), ("burst", 21)]
        .into_iter()
        .map(|(name, end)| {
            let file = format!("{name}.pcapng");
            let mut writer = PcapNgWriter::create(&root.join(&file)).unwrap();
            for no in 1..=end {
                let mut frame = router_advertisement(10, 1);
                if no == 20 { frame[18 + 40 + 2] ^= 1; }
                writer.write_packet(&parse_ethernet(&frame, no, no as f64 / 100.0)).unwrap();
            }
            writer.flush().unwrap();
            let count = usize::from(end == 21);
            let mut case = json!({"name":name,"capture":file,"expect_counts":{(rule):count},"expect_snapshots":count});
            if count != 0 {
                let frames: Vec<_> = (1..=19).chain([21]).collect();
                case["opening_frames"] = json!({(rule):[21]});
                case["opening_evidence"] = json!([{"rule_id":rule,"opening_frame":21,"frames":frames,
                    "classification":{"severity":"MEDIUM","confidence":"correlated","revision":2}}]);
            }
            case
        })
        .collect();
    let manifest = root.join("router-burst.json");
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":cases}).to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr));
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn control_plane_replay_attributes_only_supported_indications_to_their_frames() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let ndp = "ipv6.ndp_invalid_hop_limit";
    let stp = "stp.topology_change_indication";
    let cases = [
        (
            "normal-and-partial-ndp",
            ndp,
            vec![router_solicitation(10, 255), router_solicitation(10, 64)],
            true,
            &[][..],
        ),
        (
            "bad-ndp-hop-limit-on-two-vlans",
            ndp,
            vec![router_solicitation(10, 64), router_solicitation(20, 64)],
            false,
            &[1, 2][..],
        ),
        (
            "stp-ack-and-partial-change",
            stp,
            vec![configuration_bpdu(10, 0x80), configuration_bpdu(10, 1)],
            true,
            &[][..],
        ),
        (
            "stp-change-on-two-vlans",
            stp,
            vec![configuration_bpdu(10, 1), configuration_bpdu(20, 1)],
            false,
            &[1, 2][..],
        ),
    ];
    let mut labels = Vec::new();
    for (name, rule, wire_frames, partial, openings) in cases {
        let capture = format!("{name}.pcapng");
        let mut writer = PcapNgWriter::create(&root.join(&capture)).unwrap();
        for (index, mut frame) in wire_frames.into_iter().enumerate() {
            let no = index as u64 + 1;
            let wire_length = frame.len() as u32;
            if partial && index == 1 {
                frame.truncate(frame.len() - if rule == ndp { 7 } else { 1 });
            }
            let mut packet = parse_ethernet(&frame, no, no as f64);
            packet.capture = Some(CaptureMetadata {
                wire_length,
                captured_length: frame.len() as u32,
                link_type: 1,
                section_id: 0,
                interface_id: 0,
                interface_name: None,
                comments: Vec::new(),
                timestamp: Some(CaptureTimestamp {
                    ticks: no,
                    resolution: TimestampResolution::Decimal(0),
                    offset_seconds: 0,
                }),
            });
            writer.write_packet(&packet).unwrap();
        }
        writer.flush().unwrap();
        let crossing = "vlan.mac_crossing";
        let mut case = json!({
            "name": name, "capture": capture, "allow_truncated": partial,
            "expect_counts": {(rule):openings.len(), (crossing):0},
            "expect_snapshots": openings.len(),
        });
        if !openings.is_empty() {
            // The same Ethernet source is visible on both VLANs in these fixtures.
            case["expect_counts"][crossing] = json!(1);
            case["expect_snapshots"] = json!(openings.len() + 1);
            case["opening_frames"] = json!({(rule):openings,(crossing):[2]});
            let mut evidence = openings
                .iter()
                .map(|frame| json!({"rule_id":rule,"opening_frame":frame,"frames":[frame]}))
                .collect::<Vec<_>>();
            evidence.push(json!({"rule_id":crossing,"opening_frame":2,"frames":[1,2]}));
            case["opening_evidence"] = json!(evidence);
        }
        labels.push(case);
    }
    let manifest = root.join("control-plane.json");
    std::fs::write(
        &manifest,
        json!({"version":1,"strict":true,"cases":labels}).to_string(),
    )
    .unwrap();
    let output = run_suite(&manifest);
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 4);
    for (case, expected) in report["cases"].as_array().unwrap().iter().zip([1, 0, 1, 0]) {
        assert_eq!(case["summary"]["truncated_frames"], expected);
    }
}
