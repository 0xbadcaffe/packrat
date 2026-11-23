use super::{PcapNgWriter, json, run_suite};

#[path = "../support/dhcp.rs"]
mod fixture;

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn dhcp_replay_keeps_the_latest_server_evidence_for_tied_capture_times() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let rule = "dhcp.new_server_identifier";
    let cases: Vec<_> = [
        ("redundant-replies", [1, 1, 1], 0),
        ("distinct-servers", [250, 1, 2], 2),
    ]
    .into_iter()
    .map(|(name, identifiers, count)| {
        let file = format!("{name}.pcapng");
        let mut writer = PcapNgWriter::create(&root.join(&file)).unwrap();
        for (index, server) in identifiers.into_iter().enumerate() {
            let mut packet = fixture::dhcp_packet(
                index as u64 + 1,
                2,
                [2, 0, 0, 0, 0, 1],
                [2, 0, 0, 0, 0, 2],
                Some([10, 0, 0, server]),
            );
            packet.timestamp = 1.0;
            writer.write_packet(&packet).unwrap();
        }
        writer.flush().unwrap();
        let mut case =
            json!({"name":name,"capture":file,"expect_snapshots":count,"expect_counts":{(rule):count}});
        if count != 0 {
            case["opening_frames"] = json!({(rule):[2,3]});
            case["opening_evidence"] = json!([
                {"rule_id":rule,"opening_frame":2,"frames":[1,2]},
                {"rule_id":rule,"opening_frame":3,"frames":[2,3]}
            ]);
        }
        case
    })
    .collect();
    let manifest = root.join("dhcp-suite.json");
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
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn dhcp_replay_does_not_compare_different_relay_networks() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let mut writer = PcapNgWriter::create(&root.join("relayed-dhcp.pcapng")).unwrap();
    for (frame, server, relay) in [(1, 1, None), (2, 2, Some(1)), (3, 3, Some(2)), (4, 4, Some(1))] {
        let reply = fixture::dhcp_packet(frame, 2, [2, 0, 0, 0, 0, server], [2; 6], Some([10, 0, 0, server]));
        let packet = if let Some(relay) = relay {
            fixture::relayed_packet(reply, [192, 0, 2, relay])
        } else {
            reply
        };
        writer.write_packet(&packet).unwrap();
    }
    writer.flush().unwrap();
    let rule = "dhcp.new_server_identifier";
    let manifest = root.join("dhcp-relay.json");
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":[{
        "name":"different relay paths and a server change on one path","capture":"relayed-dhcp.pcapng",
        "expect_snapshots":1,"expect_counts":{(rule):1},"opening_frames":{(rule):[4]},
        "opening_evidence":[{"rule_id":rule,"opening_frame":4,"frames":[2,4],
            "classification":{"severity":"MEDIUM","confidence":"correlated","revision":5}}]
    }]}).to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
}
