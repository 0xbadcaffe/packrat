#[path = "support/http.rs"]
mod support;

use std::{path::Path, process::Command};

use packrat_tui::export::pcapng::PcapNgWriter;
use serde_json::Value;

fn write_fixture(path: &Path, anchored: bool, gap: bool) {
    let request = b"GET /status HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let response = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
    let split = response.len() - 3;
    let mut writer = PcapNgWriter::create(path).unwrap();
    let mut frame = 0;
    let mut write = |sequence, flags, payload, reverse| {
        frame += 1;
        writer
            .write_packet(&support::tcp(frame, sequence, flags, payload, reverse))
            .unwrap();
    };
    if anchored {
        write(100, 0x02, &[], false);
        write(500, 0x12, &[], true);
    }
    for index in 0..5 {
        let sequence = 501 + index * response.len() as u32;
        let tail = sequence + split as u32 + u32::from(gap && index == 4);
        write(101 + index * request.len() as u32, 0x18, request, false);
        if index == 4 && anchored && !gap {
            write(tail, 0x18, &response[split..], true);
            write(sequence, 0x18, &response[..split], true);
        } else {
            write(sequence, 0x18, &response[..split], true);
            write(tail, 0x18, &response[split..], true);
        }
        write(tail, 0x18, &response[split..], true);
    }
    writer.flush().unwrap();
}

#[test]
fn split_401_bursts_use_only_complete_scoped_headers_and_keep_each_frame() {
    let scratch = tempfile::tempdir().unwrap();
    let rule = "http.unauthorized_burst";
    for (name, anchored, gap, count) in [
        ("split", true, false, 1),
        ("gap", true, true, 0),
        ("unanchored", false, false, 0),
    ] {
        let path = scratch.path().join(format!("{name}.pcapng"));
        write_fixture(&path, anchored, gap);
        let output = Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
            .args(["--expect-alert", &format!("{rule}={count}")])
            .arg(path)
            .output()
            .unwrap();
        assert!(output.status.success(), "{name}: {}", String::from_utf8_lossy(&output.stdout));
        let rows: Vec<Value> = String::from_utf8(output.stdout).unwrap().lines()
            .map(|line| serde_json::from_str(line).unwrap()).collect();
        let alerts: Vec<_> = rows.iter().filter(|row| row["type"] == "alert").collect();
        assert_eq!(alerts.len(), count);
        if count == 1 {
            let alert = &alerts[0]["alert"];
            assert_eq!(alerts[0]["opening"], true);
            assert_eq!(alert["packet_no"], 21);
            assert_eq!(alert["provenance"]["revision"], 12);
            assert!(alert["detail"].as_str().unwrap().contains("for 5/5 sampled 401 replies"));
            let mut frames: Vec<_> = alert["packet_refs"].as_array().unwrap().iter()
                .map(|frame| frame.as_u64().unwrap()).collect();
            frames.sort_unstable();
            assert_eq!(frames, (3..22).filter(|frame| (frame + 2) % 4 != 0).collect::<Vec<_>>());
        }
    }
}
