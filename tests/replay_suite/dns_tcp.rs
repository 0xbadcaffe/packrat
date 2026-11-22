use super::super::{PcapNgWriter, Value, json, run_suite};
use super::udp_frame;
use packrat_tui::net::{packet::Packet, parser::parse_ethernet};
use std::path::Path;

fn message(id: u16, name: &[u8], reply: bool) -> Vec<u8> {
    let mut body = id.to_be_bytes().to_vec();
    body.extend([if reply { 0x81 } else { 1 }, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    body.push(name.len() as u8);
    body.extend_from_slice(name);
    body.extend_from_slice(b"\x04test\0\0\x01\0\x01");
    body
}

fn framed(id: u16, name: &[u8], reply: bool) -> Vec<u8> {
    let body = message(id, name, reply);
    let mut frame = (body.len() as u16).to_be_bytes().to_vec();
    frame.extend(body);
    frame
}

fn tcp_frame(no: u64, sequence: u32, flags: u8, reply: bool, data: &[u8]) -> Packet {
    let mut raw = udp_frame(no, &[], reply, 53, 40_000).bytes;
    raw.resize(54, 0);
    raw[16..18].copy_from_slice(&((40 + data.len()) as u16).to_be_bytes());
    raw[23] = 6;
    raw[38..42].copy_from_slice(&sequence.to_be_bytes());
    raw[46] = 0x50;
    raw[47] = flags;
    raw.extend_from_slice(data);
    parse_ethernet(&raw, no, no as f64)
}

fn write_exchange(path: &Path, changed: bool, gap_filled: bool) {
    let query = framed(10, b"first", false);
    let mut queries = query[5..].to_vec();
    queries.extend(framed(11, b"second", false));
    let name = if changed {
        &b"other"[..]
    } else {
        &b"first"[..]
    };
    let mut replies = framed(10, name, true);
    replies.extend(framed(11, b"second", true));
    let mut writer = PcapNgWriter::create(path).unwrap();
    for packet in [
        tcp_frame(1, 100, 0x02, false, &[]),
        tcp_frame(2, 500, 0x12, true, &[]),
        tcp_frame(3, 101, 0x18, false, &query[..5]),
        tcp_frame(4, 106, 0x18, false, &queries),
        tcp_frame(5, 505, 0x18, true, &replies[4..]),
        tcp_frame(6, 505, 0x18, true, &replies[4..]),
    ] {
        writer.write_packet(&packet).unwrap();
    }
    if gap_filled {
        writer
            .write_packet(&tcp_frame(7, 501, 0x18, true, &replies[..4]))
            .unwrap();
    }
    writer.flush().unwrap();
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn tcp_dns_replay_preserves_framing_transport_scope_and_evidence() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let mismatch = "dns.question_mismatch";
    let unmatched = "dns.unmatched_response";
    let mut cases = Vec::new();
    for (name, changed, filled) in [
        ("coalesced-consistent", false, true),
        ("out-of-order-mismatch", true, true),
        ("unfilled-gap", true, false),
    ] {
        let capture = format!("{name}.pcapng");
        write_exchange(&root.join(&capture), changed, filled);
        let count = usize::from(changed && filled);
        let mut case = json!({
            "name":name, "capture":capture, "expect_snapshots":count,
            "expect_counts":{(mismatch):count,(unmatched):0},
        });
        if count != 0 {
            case["opening_frames"] = json!({(mismatch):[7]});
            case["opening_evidence"] =
                json!([{"rule_id":mismatch,"opening_frame":7,"frames":[3,4,5,7]}]);
        }
        cases.push(case);
    }
    let capture = "udp-is-not-tcp.pcapng";
    let mut writer = PcapNgWriter::create(&root.join(capture)).unwrap();
    writer
        .write_packet(&udp_frame(
            1,
            &message(10, b"first", false),
            false,
            53,
            40_000,
        ))
        .unwrap();
    writer
        .write_packet(&tcp_frame(2, 501, 0x18, true, &framed(10, b"first", true)))
        .unwrap();
    writer.flush().unwrap();
    cases.push(json!({
        "name":"separate-transports", "capture":capture, "expect_snapshots":1,
        "expect_counts":{(mismatch):0,(unmatched):1},
        "opening_frames":{(unmatched):[2]},
        "opening_evidence":[{"rule_id":unmatched,"opening_frame":2,"frames":[2]}],
    }));

    let manifest = root.join("tcp-dns.json");
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
        String::from_utf8_lossy(&output.stdout)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 4);
    assert_eq!(output.stdout, run_suite(&manifest).stdout);
}
