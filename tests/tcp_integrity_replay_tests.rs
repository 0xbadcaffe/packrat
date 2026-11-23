#[path = "support/packets.rs"]
mod packets;

use packrat_tui::export::pcapng::PcapNgWriter;
use packrat_tui::net::parser::parse_ethernet;
use serde_json::{Value, json};
use std::process::Command;

#[test]
fn tcp_reset_replay_reports_peer_data_before_the_same_sender_update() {
    let fixture = tempfile::tempdir().unwrap();
    let capture = fixture.path().join("post-reset.pcapng");
    let mut writer = PcapNgWriter::create(&capture).unwrap();
    let peer_packet = |frame| {
        let mut bytes = packets::tcp(frame, 200, 0x18, b"in flight").bytes;
        for offset in 0..4 {
            bytes.swap(26 + offset, 30 + offset);
        }
        for offset in 0..2 {
            bytes.swap(34 + offset, 36 + offset);
        }
        parse_ethernet(&bytes, frame, frame as f64)
    };
    for packet in [
        packets::tcp(1, 100, 0x04, b""),
        peer_packet(2),
        peer_packet(3),
        packets::tcp(4, 101, 0x18, b"same sender"),
    ] {
        writer.write_packet(&packet).unwrap();
    }
    writer.flush().unwrap();

    let rule = "tcp.payload_after_observed_reset";
    let output = Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
        .arg("--expect-alert")
        .arg(format!("{rule}=1"))
        .arg("--expect-alert-frame")
        .arg(format!("{rule}=2"))
        .arg(&capture)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let alerts: Vec<_> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|row| row["type"] == "alert")
        .collect();
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0]["alert"]["id"], alerts[1]["alert"]["id"]);
    assert_eq!(alerts[0]["alert"]["severity"], "LOW");
    assert_eq!(alerts[0]["alert"]["packet_refs"], json!([1, 2]));
    assert_eq!(alerts[1]["alert"]["severity"], "MEDIUM");
    assert_eq!(alerts[1]["alert"]["packet_refs"], json!([1, 2, 4]));
}
