use super::super::{
    CaptureMetadata, CaptureTimestamp, PcapNgWriter, TimestampResolution, Value, json, run_suite,
};
use super::{message, udp_frame};
use std::path::Path;

#[derive(Clone, Copy)]
enum Scenario {
    Burst,
    Retries,
    LowEntropy,
    SplitVlans,
    SplitInterfaces,
    SplitWindow,
}

fn write_fixture(path: &Path, scenario: Scenario) {
    let mut capture = PcapNgWriter::create(path).unwrap();
    for frame in 1_u64..=9 {
        let index = if matches!(scenario, Scenario::Retries) {
            1
        } else {
            frame.saturating_sub(1).max(1)
        };
        let prefix = if matches!(scenario, Scenario::LowEntropy) {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        } else {
            "abcdefghijklmnpqrstuvwxyz234567"
        };
        let mut name = format!("{prefix}{index}.example");
        if frame == 2 {
            name.make_ascii_uppercase();
        }
        let dns = message(frame as u16, name.as_bytes(), false);
        let mut packet = udp_frame(frame, &dns, false, 53, 40_000);
        let second_group = frame >= 6;
        let vlan = if second_group && matches!(scenario, Scenario::SplitVlans) {
            20
        } else {
            10
        };
        packet.bytes.splice(12..12, [0x81, 0, 0, vlan]);
        let length = packet.bytes.len() as u32;
        let ticks = frame
            + if second_group && matches!(scenario, Scenario::SplitWindow) {
                60
            } else {
                0
            };
        packet.timestamp = ticks as f64;
        packet.length = length as u16;
        packet.capture = Some(CaptureMetadata {
            timestamp: Some(CaptureTimestamp {
                ticks,
                resolution: TimestampResolution::Decimal(0),
                offset_seconds: 0,
            }),
            captured_length: length,
            wire_length: length,
            link_type: 1,
            section_id: 0,
            interface_id: u32::from(second_group && matches!(scenario, Scenario::SplitInterfaces)),
            interface_name: None,
            comments: Vec::new(),
        });
        capture.write_packet(&packet).unwrap();
    }
    capture.flush().unwrap();
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn udp_dns_entropy_replay_requires_distinct_queries_in_one_capture_path_and_window() {
    use Scenario::*;

    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let rule = "dns.high_entropy_query_burst";
    let cases: Vec<_> = [
        ("distinct-burst", Burst),
        ("same-name-different-id", Retries),
        ("distinct-low-entropy", LowEntropy),
        ("split-vlans", SplitVlans),
        ("split-interfaces", SplitInterfaces),
        ("outside-window", SplitWindow),
    ]
    .into_iter()
    .map(|(name, scenario)| {
        let file = format!("{name}.pcapng");
        write_fixture(&root.join(&file), scenario);
        let expected = usize::from(matches!(scenario, Burst));
        let mut case = json!({
            "name":name, "capture":file, "expect_counts":{(rule):expected},
            "expect_snapshots":expected,
        });
        if expected != 0 {
            case["opening_frames"] = json!({(rule):[9]});
            case["opening_evidence"] = json!([{
                "rule_id":rule, "opening_frame":9, "frames":[1,3,4,5,6,7,8,9],
                "classification":{"severity":"MEDIUM","confidence":"heuristic","revision":4},
            }]);
        }
        case
    })
    .collect();
    let manifest = root.join("udp-dns-entropy.json");
    std::fs::write(
        &manifest,
        json!({"version":1,"strict":true,"cases":cases}).to_string(),
    )
    .unwrap();
    let result = run_suite(&manifest);
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["passed"], 6);
}
