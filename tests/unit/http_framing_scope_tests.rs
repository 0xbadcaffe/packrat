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

fn at_sequence(mut packet: Packet, sequence: u32) -> Packet {
    packet.bytes[42..46].copy_from_slice(&sequence.to_be_bytes());
    packet
}

fn ipv6_request_frame(no: u64, extension: u8, sequence: u32, data: &[u8]) -> Packet {
    let ipv4 = at_sequence(request_frame(no, no as f64, 1, 0x8100, 10, 80, data), sequence);
    let tcp = &ipv4.bytes[38..];
    let mut frame = vec![0; 14 + 40 + 8];
    frame[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
    frame[14] = 0x60;
    frame[18..20].copy_from_slice(&((8 + tcp.len()) as u16).to_be_bytes());
    frame[20..22].copy_from_slice(&[extension, 64]);
    frame[22..38].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
    frame[38..54].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
    frame[54] = 6;
    frame.extend(tcp);
    parse_ethernet(&frame, no, no as f64)
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
    engine.check_tcp_integrity(&a, None);
    engine.check_tcp_integrity(&b, None);
    let buffer = |engine: &SecurityEngine, scope| {
        engine.http_headers.iter().find(|((key, _, _), _)| *key == scope)
            .map(|(_, state)| (state.bytes.clone(), state.complete)).unwrap()
    };
    let scope_a = scan_scope(&a);
    let scope_b = scan_scope(&b);
    assert_ne!(scope_a, scope_b);
    assert_eq!(buffer(&engine, scope_a), (first.to_vec(), false));
    assert_eq!(buffer(&engine, scope_b), (end.to_vec(), false));
    let end_a = at_sequence(request_frame(3, 3.0, 1, 0x8100, 10, 80, end), first.len() as u32);
    engine.check_tcp_integrity(&end_a, None);
    assert_eq!(buffer(&engine, scope_a), (Vec::new(), true));
    assert!(engine.ids_alerts.is_empty());
}

#[test]
fn header_sampler_skips_repeated_and_gapped_segments_and_accepts_sequence_wrap() {
    let first = b"GET / HTTP/1.1\r\nHost: example.test\r\n";
    let tail = b"\r\n";
    let start = 0_u32.wrapping_sub(first.len() as u32);
    let sample = |no, sequence, bytes: &[u8]| at_sequence(
        request_frame(no, no as f64, 1, 0x8100, 10, 80, bytes), sequence,
    );
    let mut engine = SecurityEngine::new();
    for packet in [sample(1, start, first), sample(2, start, first), sample(3, 5, tail)] {
        engine.check_tcp_integrity(&packet, None);
    }
    let state = engine.http_headers.values().next().unwrap();
    assert_eq!(state.next_sequence, Some(0));
    assert_eq!(state.bytes, first);
    assert_eq!(state.frames, [1]);
    assert!(!state.complete);

    engine.check_tcp_integrity(&sample(4, 0, tail), None);
    let state = engine.http_headers.values().next().unwrap();
    assert!(state.complete);
    assert_eq!(state.bytes.capacity(), 0);
    assert_eq!(state.frames.capacity(), 0);
    assert!(engine.ids_alerts.is_empty());
}

#[test]
fn reaching_the_header_limit_releases_the_sample() {
    let mut engine = SecurityEngine::new();
    let large_field = vec![b'a'; 32_768];
    engine.check_tcp_integrity(&request_frame(1, 1.0, 1, 0x8100, 10, 80, &large_field), None);
    let state = engine.http_headers.values().next().unwrap();
    assert!(state.complete);
    assert_eq!(state.bytes.capacity(), 0);
    assert_eq!(state.frames.capacity(), 0);
    assert!(engine.ids_alerts.is_empty());
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn new_connection_rearms_only_its_own_header_sampler(#[case] old_complete: bool) {
    let data = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let syn = |no, time, sequence| {
        let mut packet = at_sequence(request_frame(no, time, 1, 0x8100, 10, 80, b""), sequence);
        packet.bytes[51] = 0x02;
        packet
    };
    let own = |no, bytes: &[u8], sequence| {
        at_sequence(request_frame(no, no as f64, 1, 0x8100, 10, 80, bytes), sequence)
    };
    let mut engine = SecurityEngine::new();
    engine.update(&syn(1, 1.0, 100));
    let initial = own(2, if old_complete { data } else { &data[..data.len() - 2] }, 101);
    let other = request_frame(3, 3.0, 1, 0x8100, 20, 80, data);
    engine.update(&initial);
    engine.update(&other);
    let own_scope = scan_scope(&initial);
    let sampler = |engine: &SecurityEngine| engine.http_headers.iter()
        .find_map(|((scope, _, _), state)| (*scope == own_scope).then_some(state.complete));
    assert_eq!(sampler(&engine), Some(old_complete));
    engine.update(&syn(4, 4.0, 100));
    engine.update(&syn(5, 0.5, 200));
    assert_eq!(sampler(&engine), Some(old_complete));
    assert_eq!(engine.http_headers.len(), 2);

    engine.update(&syn(6, 6.0, 500));
    assert_eq!(sampler(&engine), None);
    assert_eq!(engine.http_headers.len(), 1);
    assert!(engine.http_headers.values().next().unwrap().complete);
    engine.update(&own(7, data, 501));
    assert_eq!(sampler(&engine), Some(true));
    assert!(engine.ids_alerts.is_empty());
}

#[test]
fn header_buffer_uses_wire_port_and_ignores_truncated_segments() {
    let data = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let mut engine = SecurityEngine::new();
    let mut non_http = request_frame(1, 1.0, 1, 0x8100, 10, 443, data);
    non_http.dst_port = Some(80);
    engine.check_tcp_integrity(&non_http, None);
    let mut http = request_frame(2, 2.0, 1, 0x8100, 10, 80, data);
    let mut truncated = http.clone();
    truncated.bytes.pop();
    engine.check_tcp_integrity(&truncated, None);
    assert!(engine.http_headers.is_empty());
    http.dst_port = None;
    engine.check_tcp_integrity(&http, None);
    assert_eq!(engine.http_headers.len(), 1);
    assert!(engine.http_headers.values().next().unwrap().complete);
    assert!(engine.ids_alerts.is_empty());
}

#[test]
fn ipv6_sampler_uses_complete_segments_after_extension_headers() {
    let first = b"GET / HTTP/1.1\r\nHost: example.test\r\n";
    let mut engine = SecurityEngine::new();
    let fragmented = ipv6_request_frame(1, 44, 0, first);
    let mut truncated = ipv6_request_frame(2, 60, 0, first);
    truncated.bytes.pop();
    engine.check_tcp_integrity(&fragmented, None);
    engine.check_tcp_integrity(&truncated, None);
    assert!(engine.http_headers.is_empty());

    let complete = ipv6_request_frame(3, 60, 0, first);
    engine.check_tcp_integrity(&complete, None);
    let ((_, flow, _), state) = engine.http_headers.iter().next().unwrap();
    assert!(flow.endpoint_a.is_ipv6() && flow.endpoint_b.is_ipv6());
    assert_eq!(state.frames, [3]);
    assert!(!state.complete);
    let end = ipv6_request_frame(4, 60, first.len() as u32, b"\r\n");
    engine.check_tcp_integrity(&end, None);
    assert!(engine.http_headers.values().next().unwrap().complete);
    assert!(engine.ids_alerts.is_empty());
}
