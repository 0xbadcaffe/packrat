use super::*;
use crate::net::{packet::CaptureMetadata, parser::parse_ethernet};

fn request_frame(no: u64, time: f64, interface: u32, tpid: u16, vid: u16, port: u16, data: &[u8]) -> Packet {
    let mut frame = vec![0; 18 + 20 + 20];
    frame[12..14].copy_from_slice(&tpid.to_be_bytes());
    frame[14..16].copy_from_slice(&vid.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18] = 0x45;
    frame[20..22].copy_from_slice(&(40 + data.len() as u16).to_be_bytes());
    frame[27] = 6;
    frame[30..34].copy_from_slice(&[192, 0, 2, 1]);
    frame[34..38].copy_from_slice(&[192, 0, 2, 2]);
    frame[38..40].copy_from_slice(&40_000_u16.to_be_bytes());
    frame[40..42].copy_from_slice(&port.to_be_bytes());
    frame[50..52].copy_from_slice(&[0x50, 0x18]);
    frame.extend(data);
    let mut packet = parse_ethernet(&frame, no, time);
    packet.capture = Some(CaptureMetadata {
        timestamp: None,
        captured_length: frame.len() as u32,
        wire_length: frame.len() as u32,
        link_type: 1,
        interface_id: interface,
        section_id: 0,
        interface_name: None,
        comments: Vec::new(),
    });
    packet
}

#[rstest::rstest]
#[case(1, 0x8100, 20, 2.0)] // Different VLAN ID
#[case(1, 0x88a8, 10, 2.0)] // Same ID, different tag type
#[case(2, 0x8100, 10, 100.0)] // Different interface and clock
fn benign_headers_with_identical_tuples_stay_on_their_paths(
    #[case] interface: u32, #[case] tpid: u16, #[case] vid: u16, #[case] time: f64,
) {
    let first = b"GET / HTTP/1.1\r\nHost: example.test\r\n";
    let end = b"\r\n";
    let a = request_frame(1, 1.0, 1, 0x8100, 10, 80, first);
    let b = request_frame(2, time, interface, tpid, vid, 80, end);
    let mut engine = SecurityEngine::new();
    engine.check_http_request_smuggling(&a);
    engine.check_http_request_smuggling(&b);
    let buffer = |engine: &SecurityEngine, scope| {
        engine.http_headers.iter().find(|((key, _, _), _)| *key == scope)
            .map(|(_, state)| (state.bytes.clone(), state.complete)).unwrap()
    };
    let scope_a = scan_scope(&a);
    let scope_b = scan_scope(&b);
    assert_ne!(scope_a, scope_b);
    assert_eq!(buffer(&engine, scope_a), (first.to_vec(), false));
    assert_eq!(buffer(&engine, scope_b), (end.to_vec(), false));
    let end_a = request_frame(3, 3.0, 1, 0x8100, 10, 80, end);
    engine.check_http_request_smuggling(&end_a);
    assert_eq!(buffer(&engine, scope_a), ([first.as_slice(), end].concat(), true));
    assert!(engine.ids_alerts.is_empty());
}

#[test]
fn header_buffer_uses_wire_port_and_ignores_truncated_segments() {
    let data = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let mut engine = SecurityEngine::new();
    let mut non_http = request_frame(1, 1.0, 1, 0x8100, 10, 443, data);
    non_http.dst_port = Some(80);
    engine.check_http_request_smuggling(&non_http);
    let mut http = request_frame(2, 2.0, 1, 0x8100, 10, 80, data);
    let mut truncated = http.clone();
    truncated.bytes.pop();
    engine.check_http_request_smuggling(&truncated);
    assert!(engine.http_headers.is_empty());
    http.dst_port = None;
    engine.check_http_request_smuggling(&http);
    assert_eq!(engine.http_headers.len(), 1);
    assert!(engine.http_headers.values().next().unwrap().complete);
    assert!(engine.ids_alerts.is_empty());
}
