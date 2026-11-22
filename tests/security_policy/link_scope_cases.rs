use packrat_tui::net::{packet::CaptureMetadata, parser::parse_ethernet, security::SecurityEngine};

#[test]
fn security_does_not_decode_tcp_after_unsupported_link_framing() {
    const TITLE: &str = "Illegal TCP flag combination";
    let base = super::ipv4_tcp_packet(1, 100, 0x03, &[]);
    let mut wire = base.bytes;
    wire.splice(12..12, [0x88, 0xa8, 0, 100, 0x81, 0, 0, 10]);
    let supported = parse_ethernet(&wire, 1, 1.0);
    assert_eq!(
        (supported.outer_vlan_id, supported.vlan_id),
        (Some(100), Some(10))
    );
    let mut deep = wire.clone();
    deep.splice(20..20, [0x81, 0, 0, 11]);
    let deep = parse_ethernet(&deep, 2, 2.0);
    assert_eq!(deep.protocol, "RAW");
    assert_eq!(deep.bytes.len(), wire.len() + 4);

    let mut unsupported = supported.clone();
    unsupported.capture = Some(CaptureMetadata {
        timestamp: None,
        captured_length: wire.len() as u32,
        wire_length: wire.len() as u32,
        link_type: 101,
        section_id: 0,
        interface_id: 0,
        interface_name: None,
        comments: Vec::new(),
    });

    let mut engine = SecurityEngine::default();
    let recognized = engine.inspect(&supported);
    assert!(
        recognized
            .ids
            .iter()
            .any(|finding| finding.alert.signature == TITLE)
    );
    for packet in [deep, unsupported] {
        assert!(engine.inspect(&packet).ids.is_empty());
    }
}
