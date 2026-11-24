use packrat_tui::export::pcapng::PcapNgWriter;
use packrat_tui::net::parser::parse_ethernet;
use std::path::Path;

#[path = "ech_config.rs"]
mod ech_config;

#[path = "../replay_suite/dns_tcp.rs"]
mod tcp_replay_tests;
#[path = "../replay_suite/dns_udp_entropy.rs"]
mod udp_entropy_replay_tests;

fn message(id: u16, name: &[u8], reply: bool) -> Vec<u8> {
    let mut body = id.to_be_bytes().to_vec();
    body.extend([if reply { 0x81 } else { 1 }, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split(|&byte| byte == b'.') {
        body.push(label.len() as u8);
        body.extend_from_slice(label);
    }
    body.extend_from_slice(b"\x04test\0\0\x01\0\x01");
    body
}

pub enum Scenario {
    Equivalent,
    ChangedAnswer,
    ChangedWire,
    EquivalentSoa,
    ChangedSoa,
    EquivalentHttps,
    ChangedHttps,
    ChangedEch,
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn dns_reply_replay_correlates_delayed_responses_within_the_reply_window() {
    use serde_json::json;

    let scratch = tempfile::tempdir().unwrap();
    let changed = "dns.changed_answers";
    let unmatched = "dns.unmatched_response";
    let mut cases = Vec::new();
    for (file, delayed_at, rcode, expected) in [
        ("repeated.pcapng", 8.0, 0, None),
        ("changed.pcapng", 8.0, 3, Some((changed, "MEDIUM", "correlated", 16, vec![1, 2, 3]))),
        ("outside-window.pcapng", 5.0, 3, Some((unmatched, "LOW", "heuristic", 8, vec![3]))),
    ] {
        let mut capture = PcapNgWriter::create(&scratch.path().join(file)).unwrap();
        for (frame, timestamp, response, code) in [(1, 1.0, false, 0), (2, 11.0, true, 0), (3, delayed_at, true, rcode)] {
            let mut wire = message(110, b"safe.example", response);
            wire[3] = code;
            let mut packet = udp_frame(frame, &wire, response, 53, 40_000);
            packet.timestamp = timestamp;
            capture.write_packet(&packet).unwrap();
        }
        capture.flush().unwrap();
        let mut case = json!({"name":file,"capture":file,"expect_snapshots":usize::from(expected.is_some()),
            "expect_counts":{(changed):0,(unmatched):0}});
        if let Some((rule, severity, confidence, revision, frames)) = expected {
            case["expect_counts"][rule] = json!(1);
            case["opening_frames"] = json!({(rule):[3]});
            case["opening_evidence"] = json!([{"rule_id":rule,"opening_frame":3,"frames":frames,
                "classification":{"severity":severity,"confidence":confidence,"revision":revision}}]);
        }
        cases.push(case);
    }
    let manifest = scratch.path().join("dns-delayed-replies.json");
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":cases}).to_string()).unwrap();
    let output = super::run_suite(&manifest);
    assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn nxdomain_replay_separates_rearmed_bursts_from_sustained_activity() {
    use serde_json::{Value, json};

    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let rule = "dns.nxdomain_distinct_names";
    let mut cases = Vec::new();
    for (file, sustained, repeated, renewed_at, expected) in [
        ("renewed.pcapng", false, false, 62.0, &[40_u64, 104][..]),
        ("outside-window.pcapng", false, false, 63.0, &[40][..]),
        ("sustained.pcapng", true, false, 62.0, &[40][..]),
        ("one-name.pcapng", false, true, 62.0, &[][..]),
    ] {
        let mut capture = PcapNgWriter::create(&root.join(file)).unwrap();
        let phases = [(0..20, 1.0), (0..12, 20.0), (20..28, 34.0), (28..40, renewed_at)];
        let mut id = 0_u16;
        for (names, start) in phases.into_iter().take(if sustained { 3 } else { 4 }) {
            for (offset, name) in names.enumerate() {
                id += 1;
                let frame = u64::from(id) * 2 - 1;
                let name = format!("missing{}.example", if repeated { 0 } else { name });
                for reply in [false, true] {
                    let mut wire = message(id, name.as_bytes(), reply);
                    if reply { wire[3] = 0x83; }
                    let mut packet = udp_frame(frame + u64::from(reply), &wire, reply, 53, 40_000);
                    packet.timestamp = start + offset as f64 / 10.0 + f64::from(u8::from(reply)) / 100.0;
                    capture.write_packet(&packet).unwrap();
                }
            }
        }
        capture.flush().unwrap();
        let mut case = json!({
            "name":file, "capture":file, "expect_snapshots":expected.len(),
            "expect_counts":{(rule):expected.len()},
        });
        if !expected.is_empty() {
            case["opening_frames"] = json!({(rule):expected});
            case["opening_evidence"] = json!(expected.iter().map(|&frame| json!({
                "rule_id":rule, "opening_frame":frame, "frames":(frame - 39..=frame).collect::<Vec<_>>(),
                "classification":{"severity":"MEDIUM","confidence":"correlated","revision":7},
            })).collect::<Vec<_>>());
        }
        cases.push(case);
    }
    let manifest = root.join("dns-negative-episodes.json");
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":cases}).to_string()).unwrap();
    let output = super::run_suite(&manifest);
    assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert_eq!(serde_json::from_slice::<Value>(&output.stdout).unwrap()["passed"], 4);
}

pub fn write_fixture(path: &Path, scenario: Scenario) {
    write_answer_sequence(path, scenario, false, None);
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn dns_answer_change_replay_does_not_borrow_queries_across_vlan_tag_paths() {
    use serde_json::json;

    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    write_answer_sequence(&root.join("same-path.pcapng"), Scenario::ChangedAnswer, false, Some(false));
    write_answer_sequence(&root.join("other-path.pcapng"), Scenario::ChangedAnswer, false, Some(true));
    let manifest = root.join("dns-tag-paths.json");
    let labels = json!({"version":1,"strict":true,"cases":[
        {"name":"answer changed on the query path","capture":"same-path.pcapng","expect_snapshots":1,
         "expect_counts":{"dns.changed_answers":1,"dns.unmatched_response":0},
         "opening_frames":{"dns.changed_answers":[4]},
         "opening_evidence":[{"rule_id":"dns.changed_answers","opening_frame":4,"frames":[1,2,4]}]},
        {"name":"different answer on a separate tag path","capture":"other-path.pcapng","expect_snapshots":1,
         "expect_counts":{"dns.changed_answers":0,"dns.unmatched_response":1},
         "opening_frames":{"dns.unmatched_response":[4]},
         "opening_evidence":[{"rule_id":"dns.unmatched_response","opening_frame":4,"frames":[4]}]}
    ]});
    std::fs::write(&manifest, labels.to_string()).unwrap();
    let output = super::run_suite(&manifest);
    assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

fn write_answer_sequence(path: &Path, scenario: Scenario, early_alternate: bool, tagged_paths: Option<bool>) {
    let rr_type = match scenario {
        Scenario::ChangedWire => 65_280_u16,
        Scenario::EquivalentSoa | Scenario::ChangedSoa => 6,
        Scenario::EquivalentHttps | Scenario::ChangedHttps | Scenario::ChangedEch => 65,
        _ => 1,
    };
    let mut capture = PcapNgWriter::create(path).unwrap();
    for frame in 1..=if tagged_paths.is_some() { 4 } else { 5 } {
        let response = frame != 1;
        let equivalent_variation = matches!(frame, 3 | 5) && matches!(rr_type, 1 | 6 | 65);
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
        let qtype = if matches!(rr_type, 6 | 65) { rr_type } else { 1 };
        dns.extend_from_slice(&qtype.to_be_bytes());
        dns.extend_from_slice(&[0, 1]);
        if response {
            let changed = frame >= 4 && !matches!(scenario,
                Scenario::Equivalent | Scenario::EquivalentSoa | Scenario::EquivalentHttps);
            let value = if changed { 2 } else { 1 };
            let address = [192, 0, 2, value];
            let opaque = [value];
            let typed_data;
            let rdata: &[u8] = match rr_type {
                1 => &address,
                6 => {
                    typed_data = soa_rdata(equivalent_variation, u32::from(value));
                    &typed_data
                }
                65 => {
                    let ech_changed = changed && matches!(scenario, Scenario::ChangedEch);
                    typed_data = https_rdata(equivalent_variation, changed && !ech_changed, ech_changed);
                    &typed_data
                }
                _ => &opaque,
            };
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
        let mut packet = udp_frame(capture_frame, &dns, response, 53, 40_000);
        if let Some(split) = tagged_paths {
            let tpid = if split && frame == 4 { 0x88a8_u16 } else { 0x8100_u16 };
            let tci = if frame % 2 == 0 { 0xb014_u16 } else { 20_u16 };
            packet.bytes.splice(12..12, [tpid, tci].into_iter().flat_map(u16::to_be_bytes));
        }
        capture.write_packet(&packet).unwrap();
    }
    capture.flush().unwrap();
}

fn soa_rdata(uncompressed: bool, serial: u32) -> Vec<u8> {
    let mut data = if uncompressed {
        b"\x02NS\x04SAFE\x07EXAMPLE\0\x05ADMIN\x04SAFE\x07EXAMPLE\0".to_vec()
    } else {
        b"\x02ns\xc0\x0c\x05admin\xc0\x0c".to_vec()
    };
    for value in [serial, 3_600, 600, 86_400, 60] {
        data.extend(value.to_be_bytes());
    }
    data
}

fn https_rdata(reorder: bool, changed_port: bool, changed_ech: bool) -> Vec<u8> {
    let mut data = if reorder {
        b"\0\x01\x03CDN\x04TEST\0".to_vec()
    } else {
        b"\0\x01\x03cdn\x04test\0".to_vec()
    };
    data.extend([0, 3, 0, 2, 1, if changed_port { 0xbc } else { 0xbb }]);
    data.extend([0, 4, 0, 8]);
    for last in if reorder { [2, 1] } else { [1, 2] } {
        data.extend([192, 0, 2, last]);
    }
    let ech = ech_config::fixture(if changed_ech { 2 } else { 1 }, b"ech.test", &[]);
    data.extend(5_u16.to_be_bytes());
    data.extend(u16::try_from(ech.len()).unwrap().to_be_bytes());
    data.extend(ech);
    data
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn early_alternate_resolver_does_not_mask_later_answer_changes() {
    use serde_json::{Value, json};

    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    write_answer_sequence(&root.join("unchanged.pcapng"), Scenario::Equivalent, true, None);
    write_answer_sequence(&root.join("changed.pcapng"), Scenario::ChangedAnswer, true, None);
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
                {"rule_id": competing, "opening_frame": 3, "frames": [1, 2, 3],
                 "classification":{"severity":"CRITICAL","confidence":"correlated","revision":10}}
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

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn delayed_dns_replay_requires_a_retained_preceding_retry() {
    use serde_json::{Value, json};

    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let competing = "dns.competing_responders";
    let unmatched = "dns.unmatched_response";
    let mut cases = Vec::new();
    for (name, future_retries, extra_reply) in [("preceding-retry", 7, true), ("evicted-retry", 8, false)] {
        let file = format!("{name}.pcapng");
        let mut capture = PcapNgWriter::create(&root.join(&file)).unwrap();
        let mut frame = 0;
        let mut write = |timestamp, response, resolver| {
            frame += 1;
            let mut dns = vec![0, 49, if response { 0x81 } else { 1 }, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            dns.extend_from_slice(b"\x04safe\x07example\0\0\x01\0\x01");
            let mut packet = udp_frame(frame, &dns, response, resolver, 40_000);
            packet.timestamp = timestamp;
            capture.write_packet(&packet).unwrap();
        };
        write(1.0, false, 53);
        write(29.0, false, 53);
        for offset in 0..future_retries {
            write(38.0 + f64::from(offset), false, 53);
        }
        write(34.0, true, 53);
        if extra_reply {
            write(35.0, true, 54);
        }
        capture.flush().unwrap();
        let (rule, frames) = if extra_reply {
            (competing, vec![1, 2, frame - 1, frame])
        } else {
            (unmatched, vec![frame])
        };
        cases.push(json!({
            "name":name,"capture":file,"expect_snapshots":1,
            "expect_counts":{(competing):usize::from(extra_reply),(unmatched):usize::from(!extra_reply)},
            "opening_frames":{(rule):[frame]},
            "opening_evidence":[{"rule_id":rule,"opening_frame":frame,"frames":frames}]
        }));
    }
    let manifest = root.join("delayed-retries.json");
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":cases}).to_string()).unwrap();
    let result = super::run_suite(&manifest);
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stdout));
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
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
