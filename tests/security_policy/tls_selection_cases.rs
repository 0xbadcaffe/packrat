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
    let mut raw = ipv4_tcp_packet(no, no as u32 * 1000, 0x18, payload).bytes;
    if from_server {
        raw[34..36].copy_from_slice(&443_u16.to_be_bytes());
        raw[36..38].copy_from_slice(&50000_u16.to_be_bytes());
    }
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
        client_hello,
        prefixed,
        old[..old.len() - 1].to_vec(),
    ];
    for (index, candidate) in candidates.iter().enumerate() {
        core.analyze(&https_packet(index as u64 + 1, candidate, true));
    }
    core.analyze(&https_packet(9, &old, false));
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
