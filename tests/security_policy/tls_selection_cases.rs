use super::*;
use packrat_tui::{engine::AnalysisCore, net::parser::parse_ethernet};
#[path = "../support/tls_selection.rs"]
mod tls_wire;
use tls_wire::{server_hello, tls_packet, tls_segment};

fn https_packet(no: u64, payload: &[u8], from_server: bool) -> Packet {
    let (source, destination) = if from_server { (443, 50000) } else { (50000, 443) };
    tls_packet(no, no as u32 * 1000, 0x18, source, destination, payload)
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
    core.analyze(&tls_segment(1, 1000, 0x18, &invalid_type));
    core.analyze(&tls_packet(2, 2000, 0x18, 993, 50000, &hello[..hello.len() - 1]));
    let mut udp = tls_segment(3, 3000, 0x18, &hello).bytes;
    udp.drain(42..54);
    udp[23] = 17;
    udp[38..40].copy_from_slice(&((8 + hello.len()) as u16).to_be_bytes());
    let ip_length = (udp.len() - 14) as u16;
    udp[16..18].copy_from_slice(&ip_length.to_be_bytes());
    core.analyze(&parse_ethernet(&udp, 3, 3.0));
    assert!(core.alert_center.items.iter().all(|alert| alert.source != "TLS"));

    core.analyze(&tls_segment(4, 4000, 0x18, &hello));
    core.analyze(&tls_packet(5, 5000, 0x18, 993, 50000, &hello));
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.source == "TLS").collect();
    assert_eq!(alerts.len(), 4);
    for (port, frame) in [(8443, 4), (993, 5)] {
        let scoped: Vec<_> = alerts.iter().filter(|alert| alert.flow.unwrap().source.port() == port).collect();
        assert_eq!(scoped.len(), 2);
        assert!(scoped.iter().all(|alert| alert.packet_refs == [frame]));
    }
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

#[test]
fn segmented_tls_checks_overlap_starting_before_the_stream_prefix() {
    let hello = server_hello(0x0302, 0xc011, &[]);
    for conflict in [false, true] {
        let mut core = AnalysisCore::default();
        core.analyze(&tls_segment(1, 100, 0x12, &[]));
        core.analyze(&tls_segment(2, 101, 0x18, &hello[..19]));
        let mut overlap = vec![0; 3];
        overlap.extend_from_slice(&hello[..8]);
        if conflict {
            overlap[7] ^= 1;
        }
        core.analyze(&tls_segment(3, 98, 0x18, &overlap));
        core.analyze(&tls_segment(4, 120, 0x18, &hello[19..]));
        let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.source == "TLS").collect();
        assert_eq!(alerts.len(), if conflict { 0 } else { 2 });
        assert!(alerts.iter().all(|alert| alert.packet_refs == [2, 4]));
    }
}
#[test]
fn legacy_tls_selection_does_not_share_review_state_across_tag_paths() {
    use packrat_tui::analysis::alert_center::AlertDisposition;
    let hello = server_hello(0x0302, 0xc011, &[]);
    let mut core = AnalysisCore::default();
    for (frame, tpid, tci) in [(1, 0x8100_u16, 20_u16), (2, 0x88a8, 20), (3, 0x8100, 0xb014)] {
        let mut raw = tls_segment(frame, 100 + frame as u32 * 1024, 0x18, &hello).bytes;
        raw.splice(12..12, [tpid, tci].into_iter().flat_map(u16::to_be_bytes));
        core.analyze(&parse_ethernet(&raw, frame, frame as f64));
        if frame == 1 {
            let first: Vec<_> = core.alert_center.items.iter().filter(|item| item.source == "TLS")
                .map(|item| (item.id, item.capture_id.clone())).collect();
            assert_eq!(first.len(), 2);
            for (id, capture) in first {
                assert!(core.alert_center.set_disposition(id, capture.as_deref(), AlertDisposition::Benign));
            }
        }
    }
    for title in ["TLS 1.1 selected", "RC4 selected"] {
        let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.title == title).collect();
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].packet_refs, [1, 3]);
        assert_eq!(alerts[0].disposition, AlertDisposition::Benign);
        assert_eq!(alerts[1].packet_refs, [2]);
        assert_eq!(alerts[1].disposition, AlertDisposition::New);
    }
}
