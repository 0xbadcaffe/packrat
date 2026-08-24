use packrat_tui::net::parser::parse_ethernet;

fn ipv6_frame(next_header: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + 40];
    frame[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
    frame[14] = 0x60;
    frame[18..20].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    frame[20] = next_header;
    frame[22..38].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    frame[38..54].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(payload);
    frame
}

fn tcp_header(src_port: u16, dst_port: u16) -> [u8; 20] {
    let mut tcp = [0_u8; 20];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x02;
    tcp
}

#[test]
fn parses_tcp_after_ipv6_extension_headers() {
    let mut payload = vec![43, 0, 0, 0, 0, 0, 0, 0];
    payload.extend_from_slice(&[60, 0, 0, 0, 0, 0, 0, 0]);
    payload.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
    payload.extend_from_slice(&tcp_header(40_000, 443));

    let packet = parse_ethernet(&ipv6_frame(0, &payload), 1, 1.0);

    assert_eq!(packet.protocol, "HTTPS");
    assert_eq!(packet.src_port, Some(40_000));
    assert_eq!(packet.dst_port, Some(443));
}

#[test]
fn parses_first_fragment_but_not_non_initial_fragment_as_tcp() {
    let mut first = vec![6, 0, 0, 0, 0, 0, 0, 1];
    first.extend_from_slice(&tcp_header(12_345, 80));
    let first = parse_ethernet(&ipv6_frame(44, &first), 1, 1.0);
    assert_eq!(first.protocol, "HTTP");
    assert_eq!(first.src_port, Some(12_345));

    let non_initial = [6, 0, 0, 8, 0, 0, 0, 1, 0xaa, 0xbb];
    let non_initial = parse_ethernet(&ipv6_frame(44, &non_initial), 2, 2.0);
    assert_eq!(non_initial.protocol, "IPv6-FRAG");
    assert_eq!(non_initial.src_port, None);
}

#[test]
fn rejects_truncated_and_excessively_chained_ipv6_extensions() {
    let truncated = parse_ethernet(&ipv6_frame(0, &[6]), 1, 1.0);
    assert_eq!(truncated.protocol, "RAW");

    let mut chained = Vec::new();
    for _ in 0..17 {
        chained.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
    }
    let chained = parse_ethernet(&ipv6_frame(0, &chained), 2, 2.0);
    assert_eq!(chained.protocol, "RAW");
}
