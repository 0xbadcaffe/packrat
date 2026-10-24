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
