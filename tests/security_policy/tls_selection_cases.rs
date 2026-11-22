use super::*;
use packrat_tui::{engine::AnalysisCore, net::parser::parse_ethernet};

fn server_hello(version: u16, cipher: u16, extensions: &[u8]) -> Vec<u8> {
    let mut body = version.to_be_bytes().to_vec();
    body.extend([0x7f; 32]);
    body.push(0); // Session ID length.
    body.extend(cipher.to_be_bytes());
    body.push(0); // No compression.
    if !extensions.is_empty() {
        body.extend((extensions.len() as u16).to_be_bytes());
        body.extend(extensions);
    }
    let mut record = vec![0x16, 3, 1]; // This compatibility field is never the selected version.
    record.extend(((body.len() + 4) as u16).to_be_bytes());
    record.extend([2, 0, 0, body.len() as u8]);
    record.extend(body);
    record
}

fn https_packet(no: u64, payload: &[u8], from_server: bool) -> Packet {
    let (source, destination) = if from_server { (443, 50000) } else { (50000, 443) };
    tls_packet(no, source, destination, payload)
}

fn tls_packet(no: u64, source: u16, destination: u16, payload: &[u8]) -> Packet {
    let mut raw = ipv4_tcp_packet(no, no as u32 * 1000, 0x18, payload).bytes;
    raw[34..36].copy_from_slice(&source.to_be_bytes());
    raw[36..38].copy_from_slice(&destination.to_be_bytes());
    parse_ethernet(&raw, no, no as f64)
}

#[test]
fn tls_alerts_require_complete_server_selections() {
    let mut core = AnalysisCore::default();
    let old = server_hello(0x0301, 0x002f, &[]);
    let mut client_hello = old.clone();
    client_hello[5] = 1;
    let mut prefixed = vec![0];
    prefixed.extend(&old);
    let candidates = [
        server_hello(0x0303, 0x000a, &[]), // 3DES, not RC4.
        server_hello(0x0303, 0x1301, &[0, 43, 0, 2, 3, 4]),
        server_hello(0x0301, 0x002f, &[0, 43, 0, 2, 3, 4]), // Inconsistent version extension.
        server_hello(0x0301, 0x002f, &[0, 1, 0, 6, 0]), // Truncated extension.
        vec![0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 5], // Standalone OID is not a certificate.
        client_hello.clone(),
        prefixed,
        old[..old.len() - 1].to_vec(),
    ];
    for (index, candidate) in candidates.iter().enumerate() {
        core.analyze(&https_packet(index as u64 + 1, candidate, true));
    }
    core.analyze(&https_packet(9, &client_hello, false));
    assert!(core.alert_center.items.iter().all(|alert| !matches!(alert.source.as_str(), "TLS" | "EXPOSURE")));

    for (no, version, cipher, rule_id) in [
        (10, 0x0300, 0x002f, "tls.ssl30_selected"),
        (11, 0x0301, 0x002f, "tls.tls10_selected"),
        (12, 0x0302, 0x002f, "tls.tls11_selected"),
        (13, 0x0303, 0x0005, "tls.rc4_selected"),
    ] {
        let packet = https_packet(no, &server_hello(version, cipher, &[]), true);
        core.analyze(&packet);
        let alert = core.alert_center.items.iter().find(|alert| {
            alert.provenance.as_ref().is_some_and(|rule| rule.rule_id == rule_id)
        }).unwrap();
        assert_eq!(alert.packet_refs, [no]);
        assert_eq!(alert.severity, "MEDIUM");
        assert_eq!(alert.flow.unwrap().source.port(), 443);
        assert!(alert.detail.contains("handshake completion unverified"));
    }
    assert_eq!(core.alert_center.items.iter().filter(|alert| alert.source == "TLS").count(), 4);
}

#[test]
fn rc4_selection_covers_rfc_cipher_suites_without_matching_adjacent_suites() {
    let mut security = SecurityEngine::default();
    let mut selected_rc4 = |cipher, extensions: &[u8]| {
        let hello = server_hello(0x0303, cipher, extensions);
        let findings = security.inspect(&https_packet(1, &hello, true));
        findings.tls.iter().any(|alert| alert.kind == "RC4 selected")
    };
    for suite in [
        0x0003, 0x0004, 0x0005, 0x0017, 0x0018, 0x0020, 0x0024, 0x0028, 0x002b,
        0x008a, 0x008e, 0x0092, 0xc002, 0xc007, 0xc00c, 0xc011, 0xc016, 0xc033,
    ] {
        assert!(selected_rc4(suite, &[]), "missed RC4 suite {suite:#06x}");
    }
    for suite in [0x0019, 0x008b, 0x008f, 0xc003, 0xc010, 0xc02f, 0xc034] {
        assert!(!selected_rc4(suite, &[]), "non-RC4 suite {suite:#06x}");
    }
    assert!(!selected_rc4(0x1301, &[0, 43, 0, 2, 3, 4]));
    assert!(!selected_rc4(0xc011, &[0, 43, 0, 2, 3, 4]));
}

#[test]
fn tls_selection_on_alternate_ports_requires_a_framed_tcp_server_hello() {
    let mut core = AnalysisCore::default();
    let hello = server_hello(0x0302, 0xc011, &[]);
    let mut invalid_type = hello.clone();
    invalid_type[5] = 1;
    core.analyze(&tls_packet(1, 8443, 50000, &invalid_type));
    core.analyze(&tls_packet(2, 993, 50000, &hello[..hello.len() - 1]));
    let mut udp = tls_packet(3, 8443, 50000, &hello).bytes;
    udp.drain(42..54);
    udp[23] = 17;
    udp[38..40].copy_from_slice(&((8 + hello.len()) as u16).to_be_bytes());
    let ip_length = (udp.len() - 14) as u16;
    udp[16..18].copy_from_slice(&ip_length.to_be_bytes());
    core.analyze(&parse_ethernet(&udp, 3, 3.0));
    assert!(core.alert_center.items.iter().all(|alert| alert.source != "TLS"));

    core.analyze(&tls_packet(4, 8443, 50000, &hello));
    core.analyze(&tls_packet(5, 993, 50000, &hello));
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.source == "TLS").collect();
    assert_eq!(alerts.len(), 4);
    for (port, frame) in [(8443, 4), (993, 5)] {
        let scoped: Vec<_> = alerts.iter().filter(|alert| alert.flow.unwrap().source.port() == port).collect();
        assert_eq!(scoped.len(), 2);
        assert!(scoped.iter().all(|alert| alert.packet_refs == [frame]));
    }
}

fn tls_segment(no: u64, sequence: u32, flags: u8, payload: &[u8]) -> Packet {
    let mut wire = tls_packet(no, 8443, 50000, payload).bytes;
    wire[38..42].copy_from_slice(&sequence.to_be_bytes());
    wire[47] = flags;
    parse_ethernet(&wire, no, no as f64)
}

#[test]
fn segmented_tls_selection_uses_the_gap_fill_and_original_evidence() {
    let mut core = AnalysisCore::default();
    let hello = server_hello(0x0302, 0xc011, &[]);
    core.analyze(&tls_segment(1, 100, 0x12, &[]));
    core.analyze(&tls_segment(2, 101, 0x18, &hello[..7]));
    core.analyze(&tls_segment(3, 120, 0x18, &hello[19..]));
    core.analyze(&tls_segment(4, 120, 0x18, &hello[19..]));
    assert!(core.alert_center.items.iter().all(|alert| alert.source != "TLS"));

    core.analyze(&tls_segment(5, 108, 0x18, &hello[7..19]));
    core.analyze(&tls_segment(6, 108, 0x18, &hello[7..19]));
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.source == "TLS").collect();
    assert_eq!(alerts.len(), 2);
    for alert in alerts {
        assert_eq!(alert.packet_no, 5);
        assert_eq!(alert.packet_refs, [2, 3, 5]);
        assert_eq!(alert.hit_count, 1);
        assert_eq!(alert.flow.unwrap().source.port(), 8443);
        assert!(alert.detail.contains("reassembled ServerHello"));
    }
}

#[test]
fn segmented_tls_selection_rejects_unanchored_or_conflicting_prefixes() {
    let hello = server_hello(0x0302, 0xc011, &[]);
    for anchored in [false, true] {
        let mut core = AnalysisCore::default();
        if anchored {
            core.analyze(&tls_segment(1, 100, 0x12, &[]));
        }
        core.analyze(&tls_segment(2, 101, 0x18, &hello[..19]));
        if anchored {
            let mut conflicting = hello[7..12].to_vec();
            conflicting[0] ^= 1;
            core.analyze(&tls_segment(3, 108, 0x18, &conflicting));
        }
        core.analyze(&tls_segment(4, 120, 0x18, &hello[19..]));
        assert!(core.alert_center.items.iter().all(|alert| alert.source != "TLS"));
    }
}
