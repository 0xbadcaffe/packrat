use super::*;
use packrat_tui::{engine::AnalysisCore, net::parser::parse_ethernet};

#[test]
fn basic_authorization_requires_a_wire_request_and_redacts_credentials() {
    const TITLE: &str = "Cleartext HTTP Basic authorization";
    let request = b"POST /login HTTP/1.1\r\nHost: example.test\r\naUtHoRiZaTiOn: bAsIc  cTE6cA==\r\n\r\n";
    let make = |no, port: u16, payload: &[u8]| {
        let mut frame = ipv4_tcp_packet(no, no as u32 * 1000, 0x18, payload).bytes;
        frame[36..38].copy_from_slice(&port.to_be_bytes());
        parse_ethernet(&frame, no, no as f64)
    };
    let mut core = AnalysisCore::default();
    let controls: [&[u8]; 8] = [
        b"GET /admin HTTP/1.1\r\nHost: example.test\r\n\r\n",
        b"GET / HTTP/1.1\r\n\r\nAuthorization: Basic cTE6cA==\r\n",
        b"HTTP/1.1 401 Unauthorized\r\nAuthorization: Basic cTE6cA==\r\n\r\n",
        b"GET / HTTP/1.1\r\nAuthorization: Bearer cTE6cA==\r\n\r\n",
        b"GET / HTTP/1.1\r\nAuthorization: Basic cTE=\r\n\r\n",
        b"GET / HTTP/1.1\r\nAuthorization: Basic cTE6cB==\r\n\r\n",
        b"GET / HTTP/1.1\r\nX-Test: Authorization: Basic cTE6cA==\r\n\r\n",
        &request[..request.len() - 2],
    ];
    for (index, payload) in controls.iter().enumerate() {
        core.analyze(&make(index as u64 + 1, 80, payload));
    }
    core.analyze(&make(9, 443, request));
    assert!(core.alert_center.items.iter().all(|alert| {
        alert.title != TITLE && alert.title != "Cleartext HTTP Sensitive Path"
    }));

    core.analyze(&make(10, 80, request));
    core.analyze(&make(11, 3128,
        b"CONNECT example.test:443 HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\n\r\n"));
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == TITLE).collect();
    assert_eq!(alerts.len(), 2);
    for (alert, no, port, field) in [(alerts[0], 10, 80, "Authorization"), (alerts[1], 11, 3128, "Proxy-Authorization")] {
        assert_eq!(alert.packet_refs, [no]);
        assert_eq!(alert.flow.unwrap().destination.port(), port);
        assert_eq!(alert.severity, "HIGH");
        assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "http.cleartext_basic_authorization");
        assert!(alert.detail.starts_with(field));
        let notification = serde_json::to_string(alert).unwrap();
        for secret in ["cTE6cA==", "q1:p", "dTpw", "u:p"] {
            assert!(!notification.contains(secret));
        }
    }
}
