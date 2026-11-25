use packrat_tui::net::{packet::Packet, parser::parse_ethernet, security::SecurityEngine};
use packrat_tui::{analysis::alert_center::{AlertFlow, AlertTransport}, engine::AnalysisCore};
use super::cases_2::{HTTP_SPLIT_FIRST, HTTP_SPLIT_LAST};

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

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn ipv6_http_framing_records_a_flow_only_if_metadata_matches_wire(#[case] mismatched: bool) {
    let mut core = AnalysisCore::default();
    core.analyze(&tagged_ipv6_tcp(1, 40_000, 80, HTTP_SPLIT_FIRST));
    let mut trigger = tagged_ipv6_tcp(2, 40_000, 80, HTTP_SPLIT_LAST);
    trigger.bytes[62..66].copy_from_slice(&(HTTP_SPLIT_FIRST.len() as u32).to_be_bytes());
    if mismatched {
        trigger.dst_port = Some(81);
    }
    core.analyze(&trigger);
    let finding = core.alert_center.items.iter()
        .find(|alert| alert.title == "HTTP request smuggling ambiguity").unwrap();
    assert_eq!(finding.packet_refs, [1, 2]);
    assert_eq!(finding.flow, (!mismatched).then_some(AlertFlow {
        transport: AlertTransport::Tcp,
        source: "[2001:db8::1]:40000".parse().unwrap(),
        destination: "[2001:db8::2]:80".parse().unwrap(),
    }));
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

#[test]
fn http_auth_burst_ignores_incomplete_responses_and_port_metadata_mismatches() {
    let mut security = SecurityEngine::default();
    let response = |no, wire_port: u16, payload: &[u8]| {
        let mut wire = super::ipv4_tcp_packet(no, no as u32 * 1000, 0x18, payload).bytes;
        wire[34..36].copy_from_slice(&wire_port.to_be_bytes());
        parse_ethernet(&wire, no, no as f64)
    };
    let valid = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
    for (i, partial) in [
        b"HTTP/1.1 401 Unauthorized\r\n".as_slice(),
        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n",
        b"HTTP/1.1 401 Unauthorized\r\nBrokenHeader\r\n\r\n",
        b"HTTP/1.0 401 Unauthorized\r\nContent-Length: ",
    ]
    .into_iter()
    .enumerate()
    {
        security.update(&response(i as u64 + 1, 80, partial));
    }
    let mut mismatch = response(5, 12345, valid);
    mismatch.src_port = Some(80);
    security.update(&mismatch);
    assert!(security.brute_force.is_empty());

    for no in 6..=10 {
        security.update(&response(no, 80, valid));
    }
    let [alert] = security.brute_force.as_slice() else {
        panic!("expected one HTTP response burst");
    };
    assert_eq!(alert.packet_refs, [6, 7, 8, 9, 10]);
    assert_eq!(alert.attempts, 5);
}
