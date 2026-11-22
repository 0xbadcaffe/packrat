use super::{Command, PcapNgWriter, Value, json, run_suite};

#[path = "../support/dtp.rs"]
mod wire;

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn dtp_replay_validates_snap_version_and_message_bounds() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let rule = "vlan.dtp_negotiation";
    let mut cases = Vec::new();
    for (name, pid, vlan, expected) in [
        ("dtp", 0x2004, None, 1),
        ("tagged-dtp", 0x2004, Some(10), 1),
        ("cdp", 0x2000, None, 0),
        ("vtp", 0x2003, None, 0),
        ("wrong-version", 0x2004, None, 0),
        ("truncated-body", 0x2004, None, 0),
        ("invalid-tlv", 0x2004, None, 0),
    ] {
        let mut packet = wire::fixture(1, pid, vlan);
        match name {
            "wrong-version" => packet.bytes[22] = 2,
            "truncated-body" => {
                packet.bytes.truncate(25);
                packet.length = 25;
            }
            "invalid-tlv" => packet.bytes[25..27].copy_from_slice(&12_u16.to_be_bytes()),
            _ => {}
        }
        let capture = format!("{name}.pcapng");
        let mut writer = PcapNgWriter::create(&root.join(&capture)).unwrap();
        writer.write_packet(&packet).unwrap();
        writer.flush().unwrap();
        let mut case = json!({"name":name,"capture":capture,
            "expect_counts":{(rule):expected},"expect_snapshots":expected});
        if expected == 1 {
            case["opening_frames"] = json!({(rule):[1]});
            case["opening_evidence"] = json!([{"rule_id":rule,"opening_frame":1,"frames":[1]}]);
        }
        cases.push(case);
    }
    let manifest = root.join("dtp.json");
    std::fs::write(&manifest, json!({"version":1,"strict":true,"cases":cases}).to_string()).unwrap();
    let output = run_suite(&manifest);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 7);

    let findings = Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
        .arg("--alerts-only").arg(root.join("tagged-dtp.pcapng")).output().unwrap();
    assert!(findings.status.success());
    let alert = String::from_utf8(findings.stdout).unwrap().lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|row| row["type"] == "alert").unwrap();
    assert_eq!(alert["alert"]["severity"], "INFO");
    assert_eq!(alert["alert"]["provenance"]["confidence"], "direct_observation");
}
