use super::*;

#[test]
fn parses_quic_v1_initial_invariant_header() {
    let mut packet = vec![0_u8; 42];
    packet.extend_from_slice(&[0xc0, 0, 0, 0, 1, 8]);
    packet.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    packet.push(4);
    packet.extend_from_slice(&[9, 10, 11, 12]);
    let header = parse_quic_header(&packet).unwrap();
    assert_eq!(header.version, Some(1));
    assert_eq!(header.packet_type, "Initial");
    assert_eq!(header.destination_id, "0102030405060708");
    assert!(header.ratq.starts_with("ratq1_"));
}

#[test]
fn truncated_tls_handshake_does_not_panic() {
    let packet = [0x16, 0x03, 0x03, 0x00, 0x01, 0x01];
    assert!(parse_client_hello(&packet, 't').is_none());
    assert!(parse_server_hello(&packet).is_none());
}

#[test]
fn malformed_encrypted_inputs_never_panic() {
    let cases = malformed_encrypted_inputs();
    for (name, packet) in cases {
        let result = std::panic::catch_unwind(|| {
            let _ = parse_client_hello(&packet, 't');
            let _ = parse_server_hello(&packet);
            let _ = parse_quic_header(&packet);
        });
        assert!(result.is_ok(), "{name} should not panic");
    }
}

fn malformed_encrypted_inputs() -> Vec<(&'static str, Vec<u8>)> {
    let mut cases = vec![
        ("empty", Vec::new()),
        ("one-byte-tls-record", vec![0x16]),
        ("tls-record-header-only", vec![0x16, 0x03, 0x03, 0x00, 0x10]),
        ("tls-record-shorter-than-handshake-header", vec![0x16, 0x03, 0x03, 0x00, 0x01, 0x01]),
        ("tls-record-with-oversized-handshake", vec![0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0xff, 0xff, 0xff]),
        ("tls-clienthello-short-random", vec![0x16, 0x03, 0x03, 0x00, 0x24, 0x01, 0x00, 0x00, 0x20, 0x03, 0x03]),
        ("quic-long-header-missing-version", vec![0xc0, 0x00, 0x00]),
        ("quic-long-header-oversized-dcid", vec![0xc0, 0x00, 0x00, 0x00, 0x01, 0x40]),
        ("quic-long-header-missing-scid", vec![0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 1, 2, 3]),
    ];

    let mut valid_quic_prefix = vec![0_u8; 42];
    valid_quic_prefix.extend_from_slice(&[0xc0, 0, 0, 0, 1, 8]);
    valid_quic_prefix.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    valid_quic_prefix.push(4);
    valid_quic_prefix.extend_from_slice(&[9, 10, 11, 12]);
    for len in 0..valid_quic_prefix.len() {
        cases.push(("truncated-quic-prefix", valid_quic_prefix[..len].to_vec()));
    }

    cases
}
