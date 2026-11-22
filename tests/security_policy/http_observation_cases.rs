use packrat_tui::net::{packet::Packet, parser::parse_ethernet, security::SecurityEngine};

fn tagged_ipv6_tcp(no: u64, source: u16, destination: u16, payload: &[u8]) -> Packet {
    let mut wire = vec![0; 12];
    wire.extend([0x81, 0, 0, 10, 0x86, 0xdd]);
    wire.extend([0x60, 0, 0, 0]);
    wire.extend(((24 + payload.len()) as u16).to_be_bytes());
    wire.extend([6, 64]);
    for address in ["2001:db8::1", "2001:db8::2"] {
        wire.extend(address.parse::<std::net::Ipv6Addr>().unwrap().octets());
    }
    wire.extend(source.to_be_bytes());
    wire.extend(destination.to_be_bytes());
    wire.extend([0; 8]);
    wire.extend([0x60, 0x18, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1]);
    wire.extend(payload);
    parse_ethernet(&wire, no, no as f64)
}

#[test]
fn http_observations_use_wire_payload_bounds_and_header_direction() {
    let mut security = SecurityEngine::default();
    let mut send = |no, source, destination, message: &[u8]| {
        security.update(&tagged_ipv6_tcp(no, source, destination, message))
    };
    let request = b"GET /status HTTP/1.1\r\nHost: sample.test\r\nUser-Agent: packrat-test\r\n\r\nUser-Agent: not-a-header";
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    send(1, 40000, 8080, request);
    send(2, 8080, 40000, response);
    send(
        3,
        40000,
        8080,
        b"GET /partial HTTP/1.1\r\nHost: sample.test\r\n",
    );
    send(4, 40000, 8080, response);
    send(5, 8080, 40000, request);
    send(6, 8080, 40000, b"HTTP/1.1 999 Impossible\r\n\r\n");
    let mut packet = tagged_ipv6_tcp(7, 40000, 8080, b"");
    packet.bytes.extend(request);
    security.update(&packet);

    let [request, response] = security.http_records.as_slice() else {
        panic!("expected exactly two complete HTTP observations");
    };
    assert_eq!((request.pkt_no, request.port), (1, 8080));
    assert_eq!(
        (request.method.as_str(), request.path.as_str()),
        ("GET", "/status")
    );
    assert_eq!(request.user_agent, "packrat-test");
    assert_eq!(
        (response.pkt_no, response.port, response.response_code),
        (2, 8080, Some(200))
    );
}
