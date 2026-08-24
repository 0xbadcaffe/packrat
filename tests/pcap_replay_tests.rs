use packrat_tui::pcap_replay::read_pcap;

fn pcap(frame: &[u8], link_type: u32, nanos: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(if nanos {
        &[0x4d, 0x3c, 0xb2, 0xa1]
    } else {
        &[0xd4, 0xc3, 0xb2, 0xa1]
    });
    bytes.extend_from_slice(&2_u16.to_le_bytes());
    bytes.extend_from_slice(&4_u16.to_le_bytes());
    bytes.extend_from_slice(&0_i32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&65_535_u32.to_le_bytes());
    bytes.extend_from_slice(&link_type.to_le_bytes());
    bytes.extend_from_slice(&7_u32.to_le_bytes());
    bytes.extend_from_slice(&500_000_u32.to_le_bytes());
    bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    bytes.extend_from_slice(frame);
    bytes
}

fn ipv6_tcp_frame() -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + 40 + 20];
    frame[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
    frame[14] = 0x60;
    frame[18..20].copy_from_slice(&20_u16.to_be_bytes());
    frame[20] = 6;
    frame[22..38].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    frame[38..54].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    frame[54..56].copy_from_slice(&40_000_u16.to_be_bytes());
    frame[56..58].copy_from_slice(&443_u16.to_be_bytes());
    frame[66] = 0x50;
    frame[67] = 0x02;
    frame
}

fn write_temp(contents: &[u8], label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("packrat-{label}-{}.pcap", std::process::id()));
    std::fs::write(&path, contents).unwrap();
    path
}

#[test]
fn imported_pcap_uses_the_full_ethernet_parser_for_ipv6() {
    let path = write_temp(&pcap(&ipv6_tcp_frame(), 1, true), "ipv6");
    let packets = read_pcap(&path).unwrap();
    let _ = std::fs::remove_file(path);
    assert_eq!(packets[0].protocol, "HTTPS");
    assert_eq!(packets[0].src, "2001:0db8:0000:0000:0000:0000:0000:0001");
    assert_eq!(packets[0].dst_port, Some(443));
    assert!((packets[0].timestamp - 7.0005).abs() < 1e-12);
}

#[test]
fn imported_pcap_rejects_unsupported_links_and_truncation() {
    let frame = ipv6_tcp_frame();
    let unsupported = write_temp(&pcap(&frame, 101, false), "raw-link");
    assert!(read_pcap(&unsupported).unwrap_err().contains("link type"));
    let _ = std::fs::remove_file(unsupported);

    let mut truncated = pcap(&frame, 1, false);
    truncated.pop();
    let truncated = write_temp(&truncated, "truncated");
    assert!(read_pcap(&truncated).unwrap_err().contains("Truncated"));
    let _ = std::fs::remove_file(truncated);
}
