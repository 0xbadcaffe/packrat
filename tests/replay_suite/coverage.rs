use super::*;
use sha2::{Digest, Sha256};

#[test]
fn analyzer_fingerprints_frame_coverage_in_capture_order() {
    let scratch = tempfile::tempdir().unwrap();
    for truncated_frame in [1, 2] {
        let capture = scratch.path().join(format!("truncated-{truncated_frame}.pcapng"));
        let mut writer = PcapNgWriter::create(&capture).unwrap();
        let mut flags = [1, 1];
        for frame in 1..=2 {
            let mut packet = support::tcp(frame, frame as u32 * 100, 0x18, b"sample", true);
            let captured_length = packet.bytes.len() as u32;
            let truncated = frame == truncated_frame;
            packet.capture = Some(CaptureMetadata {
                timestamp: Some(CaptureTimestamp {
                    ticks: frame,
                    resolution: TimestampResolution::Decimal(6),
                    offset_seconds: 0,
                }),
                captured_length,
                wire_length: captured_length + u32::from(truncated),
                link_type: 1,
                section_id: 0,
                interface_id: 0,
                interface_name: None,
                comments: Vec::new(),
            });
            flags[frame as usize - 1] |= u8::from(truncated) << 1;
            writer.write_packet(&packet).unwrap();
        }
        writer.flush().unwrap();
        let expected = format!("{:x}", Sha256::digest(flags));
        for options in [&[][..], &["--alerts-only"][..]] {
            let output = Command::new(env!("CARGO_BIN_EXE_packrat-analyze"))
                .args(options)
                .arg(&capture)
                .output()
                .unwrap();
            assert!(output.status.success(), "{:?}", output.stderr);
            let stdout = String::from_utf8(output.stdout).unwrap();
            let summary: Value = serde_json::from_str(stdout.lines().last().unwrap()).unwrap();
            assert_eq!(summary["type"], "summary");
            assert_eq!(summary["analyzed"], 2);
            assert_eq!(summary["truncated_frames"], 1);
            assert_eq!(summary["frame_coverage_sha256_v1"], expected);
        }
    }
}
