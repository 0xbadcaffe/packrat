use packrat_tui::export::pcapng::PcapNgWriter;
use packrat_tui::net::parser::parse_ethernet;
use std::path::Path;

#[path = "../replay_suite/dns_tcp.rs"]
mod tcp_replay_tests;

pub enum Scenario {
    Equivalent,
    ChangedAnswer,
    ChangedWire,
}

pub fn write_fixture(path: &Path, scenario: Scenario) {
    write_answer_sequence(path, scenario, false);
}

fn write_answer_sequence(path: &Path, scenario: Scenario, early_alternate: bool) {
    let rr_type = match scenario {
        Scenario::ChangedWire => 65_280_u16,
        _ => 1,
    };
    let mut capture = PcapNgWriter::create(path).unwrap();
    for frame in 1..=5 {
        let response = frame != 1;
        let equivalent_variation = frame == 3 && rr_type == 1;
        let mut dns = vec![
            0,
            49,
            if response { 0x81 } else { 1 },
            if response { 0x80 } else { 0 },
            0,
            1,
            0,
            u8::from(response),
            0,
            0,
            0,
            0,
        ];
        dns.extend_from_slice(if equivalent_variation {
            b"\x04SAFE\x07EXAMPLE\0"
        } else {
            b"\x04safe\x07example\0"
        });
        dns.extend_from_slice(&[0, 1, 0, 1]);
        if response {
            let changed = frame >= 4 && !matches!(scenario, Scenario::Equivalent);
            let value = if changed { 2 } else { 1 };
            let address = [192, 0, 2, value];
            let opaque = [value];
            let rdata: &[u8] = if rr_type == 1 { &address } else { &opaque };
            dns.extend_from_slice(&[0xc0, 0x0c]);
            dns.extend_from_slice(&rr_type.to_be_bytes());
            dns.extend_from_slice(&[0, 1]);
            dns.extend_from_slice(
                &(if equivalent_variation { 299_u32 } else { 300 }).to_be_bytes(),
            );
            dns.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            dns.extend_from_slice(rdata);
        }

        if early_alternate && frame == 2 {
            capture.write_packet(&udp_frame(frame, &dns, true, 54, 40_000)).unwrap();
        }
        let capture_frame = frame + u64::from(early_alternate && response);
        capture
            .write_packet(&udp_frame(capture_frame, &dns, response, 53, 40_000))
            .unwrap();
    }
    capture.flush().unwrap();
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn early_alternate_resolver_does_not_mask_later_answer_changes() {
    use serde_json::{Value, json};

    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    write_answer_sequence(&root.join("unchanged.pcapng"), Scenario::Equivalent, true);
    write_answer_sequence(&root.join("changed.pcapng"), Scenario::ChangedAnswer, true);
    let unexpected = "dns.unexpected_responder";
    let competing = "dns.competing_responders";
    let changed = "dns.changed_answers";
    let mut cases = Vec::new();
    for (file, has_change) in [("unchanged.pcapng", false), ("changed.pcapng", true)] {
        let mut case = json!({
            "name": file, "capture": file, "expect_snapshots": 2 + usize::from(has_change),
            "expect_counts": {(unexpected): 1, (competing): 1, (changed): usize::from(has_change)},
            "opening_frames": {(unexpected): [2], (competing): [3]},
            "opening_evidence": [
                {"rule_id": unexpected, "opening_frame": 2, "frames": [1, 2]},
                {"rule_id": competing, "opening_frame": 3, "frames": [1, 2, 3]}
            ]
        });
        if has_change {
            case["opening_frames"][changed] = json!([5]);
            case["opening_evidence"].as_array_mut().unwrap().push(json!({
                "rule_id": changed, "opening_frame": 5, "frames": [1, 3, 5]
            }));
        }
        cases.push(case);
    }
    let manifest = root.join("early-alternate.json");
    let labels = json!({"version": 1, "strict": true, "cases": cases});
    std::fs::write(&manifest, labels.to_string()).unwrap();
    let output = super::run_suite(&manifest);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 2);
}

pub fn write_parallel_transactions(path: &Path, alternate_replies: bool) {
    let mut capture = PcapNgWriter::create(path).unwrap();
    let frames = [
        (false, 53, 40_000),
        (false, 53, 40_001),
        (true, 53, 40_000),
        (true, 53, 40_001),
        (true, 54, 40_000),
        (true, 54, 40_001),
        (true, 55, 40_000),
    ];
    for (index, (response, resolver, port)) in frames.into_iter().enumerate() {
        let mut dns = vec![
            0,
            49,
            if response { 0x81 } else { 1 },
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        dns.extend_from_slice(b"\x04safe\x07example\0\0\x01\0\x01");
        let resolver = if alternate_replies { resolver } else { 53 };
        capture
            .write_packet(&udp_frame(index as u64 + 1, &dns, response, resolver, port))
            .unwrap();
    }
    capture.flush().unwrap();
}

fn udp_frame(
    frame: u64,
    dns: &[u8],
    response: bool,
    resolver: u8,
    port: u16,
) -> packrat_tui::net::packet::Packet {
    let mut bytes = vec![0_u8; 42];
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&((28 + dns.len()) as u16).to_be_bytes());
    bytes[22] = 64;
    bytes[23] = 17;
    let client = ([10, 0, 0, 5], port);
    let server = ([10, 0, 0, resolver], 53_u16);
    let ((src, sport), (dst, dport)) = if response {
        (server, client)
    } else {
        (client, server)
    };
    bytes[26..30].copy_from_slice(&src);
    bytes[30..34].copy_from_slice(&dst);
    bytes[34..36].copy_from_slice(&sport.to_be_bytes());
    bytes[36..38].copy_from_slice(&dport.to_be_bytes());
    bytes[38..40].copy_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
    bytes.extend_from_slice(dns);
    parse_ethernet(&bytes, frame, frame as f64)
}
