#[path = "support/http.rs"]
mod support;

use packrat_tui::{analysis::stream::StreamKey, engine::AnalysisCore};
use std::sync::Arc;

#[test]
fn repeated_queries_share_results_and_new_packets_invalidate_them() {
    let mut core = AnalysisCore::default();
    let packet = support::tcp(1, 100, 0x18, b"GET / HTTP/1.1\r\n\r\n", false);
    let key = StreamKey::from_packet(&packet).unwrap().id();
    core.analyze(&packet);
    let first = core.http_transactions(&key).unwrap();
    assert!(Arc::ptr_eq(&first, &core.http_transactions(&key).unwrap()));
    assert!(first.transactions[0].response.is_none());
    core.analyze(&support::tcp(
        2,
        500,
        0x18,
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        true,
    ));
    let changed = core.http_transactions(&key).unwrap();
    assert!(!Arc::ptr_eq(&first, &changed));
    assert_eq!(
        changed.transactions[0].response.as_ref().unwrap().status,
        Some(200)
    );
    core.clear();
    assert!(core.http_transactions(&key).is_none());
    assert_eq!(first.transactions.len(), 1);
}

#[test]
fn queries_do_not_change_the_detection_state_or_require_a_runtime() {
    let mut core = AnalysisCore::default();
    let packet = support::tcp(1, 100, 0x18, b"GET / HTTP/1.1\r\n\r\n", false);
    let key = StreamKey::from_packet(&packet).unwrap().id();
    core.analyze(&packet);
    let incidents = serde_json::to_value(core.incidents.snapshot()).unwrap();
    assert_eq!(core.http_transactions(&key).unwrap().transactions.len(), 1);
    assert_eq!(
        serde_json::to_value(core.incidents.snapshot()).unwrap(),
        incidents
    );
}

#[test]
fn assembler_eviction_and_reuse_cannot_return_an_old_cached_exchange() {
    let mut core = AnalysisCore::default();
    let first = support::tcp(1, 100, 0x18, b"GET /old HTTP/1.1\r\n\r\n", false);
    let id = StreamKey::from_packet(&first).unwrap().id();
    core.streams.ingest(&first);
    let old = core.http_transactions(&id).unwrap();
    for index in 0..500 {
        let packet = support::tcp(index + 2, 100, 0x02, &[], false);
        let mut raw = packet.bytes.to_vec();
        raw[34..36].copy_from_slice(&(1000 + index as u16).to_be_bytes());
        core.streams
            .ingest(&packrat_tui::net::parser::parse_ethernet(
                &raw,
                index + 2,
                (index + 2) as f64,
            ));
    }
    assert_eq!(core.streams.evicted_streams(), 1);
    assert!(core.http_transactions(&id).is_none());
    core.streams.ingest(&support::tcp(
        1000,
        500,
        0x18,
        b"GET /new HTTP/1.1\r\n\r\n",
        false,
    ));
    let new = core.http_transactions(&id).unwrap();
    assert!(!Arc::ptr_eq(&old, &new));
    assert_eq!(new.transactions[0].request.target.as_deref(), Some("/new"));
    core.streams.clear();
    assert_eq!(core.streams.evicted_streams(), 0);
}
