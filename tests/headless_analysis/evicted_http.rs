use super::{events, http2, run, run_with, support};
use packrat_tui::{export::pcapng::PcapNgWriter, net::parser::parse_ethernet};
use serde_json::json;
use std::collections::BTreeSet;

#[test]
fn tcp_conversations_survive_stream_cache_eviction_with_exact_frame_references() {
    const STREAMS: u16 = 520;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("evictions.pcapng");
    let mut writer = PcapNgWriter::create(&path).unwrap();
    let h2 = http2::stream(
        &http2::frame(1, 5, 1, &http2::request(b"/h2")),
        &http2::frame(1, 5, 1, &[0x88]),
    );
    for stream in 0..STREAMS {
        let (request, response): (&[u8], &[u8]) = if stream % 2 == 0 {
            (
                b"GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            )
        } else {
            (&h2.client_data, &h2.server_data)
        };
        for (offset, seq, bytes, reply) in [(0, 100, request, false), (1, 500, response, true)] {
            let frame = u64::from(stream) * 2 + 1 + offset;
            let mut packet = support::tcp(frame, seq, 0x18, bytes, reply);
            let start = if reply { 36 } else { 34 };
            packet.bytes[start..start + 2].copy_from_slice(&(40_000 + stream).to_be_bytes());
            writer
                .write_packet(&parse_ethernet(&packet.bytes, frame, frame as f64))
                .unwrap();
        }
    }
    writer.flush().unwrap();

    let rows = events(&run(&path));
    let mut frames = BTreeSet::new();
    let mut evicted = 0;
    for row in &rows {
        if row["type"] != "http_conversation" && row["type"] != "http2_conversation" {
            continue;
        }
        let transactions = row["conversation"]["transactions"].as_array().unwrap();
        assert_eq!(transactions.len(), 1);
        let request = transactions[0]["request"]["packet_numbers"][0]
            .as_u64()
            .unwrap();
        assert!(frames.insert(request));
        assert_eq!(
            transactions[0]["response"]["packet_numbers"],
            json!([request + 1])
        );
        match row["stream_boundary"].as_str() {
            Some("evicted") => {
                evicted += 1;
                assert!(request < 41);
            }
            Some("end_of_capture") => assert!(request >= 41),
            other => panic!("unexpected export boundary: {other:?}"),
        }
    }
    assert!(
        frames
            .into_iter()
            .eq((1..=u64::from(STREAMS) * 2).step_by(2))
    );
    assert_eq!(evicted, 20);
    let summary = rows.last().unwrap();
    assert_eq!(summary["http_exchanges"], STREAMS);
    assert_eq!(summary["http1_exchanges"], STREAMS / 2);
    assert_eq!(summary["http2_exchanges"], STREAMS / 2);
    assert_eq!(summary["retained_streams"], 500);
    assert_eq!(summary["evicted_streams"], evicted);

    let alerts_only = events(&run_with(&path, &["--alerts-only"]));
    assert!(
        alerts_only
            .iter()
            .all(|row| row["type"] == "alert" || row["type"] == "summary")
    );
    let alert_summary = alerts_only.last().unwrap();
    assert_eq!(alert_summary["alerts_opened"], summary["alerts_opened"]);
    assert_eq!(
        alert_summary["frame_coverage_sha256_v1"],
        summary["frame_coverage_sha256_v1"]
    );
}
