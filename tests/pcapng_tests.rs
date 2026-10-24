use packrat_tui::pcap_replay::read_pcap;

fn number(value: u32, big: bool) -> [u8; 4] {
    if big {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    }
}

fn short(value: u16, big: bool) -> [u8; 2] {
    if big {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    }
}

fn block(kind: u32, mut body: Vec<u8>, big: bool) -> Vec<u8> {
    while body.len() % 4 != 0 {
        body.push(0);
    }
    let length = (body.len() + 12) as u32;
    let mut result = number(kind, big).to_vec();
    result.extend(number(length, big));
    result.extend(body);
    result.extend(number(length, big));
    result
}

fn option(code: u16, data: &[u8], big: bool) -> Vec<u8> {
    let mut result = short(code, big).to_vec();
    result.extend(short(data.len() as u16, big));
    result.extend(data);
    while result.len() % 4 != 0 {
        result.push(0);
    }
    result
}

fn section(big: bool, resolution: u8, offset: i64, link: u16) -> Vec<u8> {
    let mut header = number(0x1a2b3c4d, big).to_vec();
    header.extend(short(1, big));
    header.extend(short(0, big));
    header.extend([0xff; 8]);
    let mut result = block(0x0a0d0d0a, header, big);
    let mut interface = short(link, big).to_vec();
    interface.extend(short(0, big));
    interface.extend(number(65535, big));
    interface.extend(option(2, b"sensor0", big));
    interface.extend(option(9, &[resolution], big));
    interface.extend(option(
        14,
        &if big {
            offset.to_be_bytes()
        } else {
            offset.to_le_bytes()
        },
        big,
    ));
    interface.extend(option(0, &[], big));
    result.extend(block(1, interface, big));
    result
}

fn enhanced(big: bool, interface: u32, ticks: u64, data: &[u8], wire: u32) -> Vec<u8> {
    let mut result = Vec::new();
    for value in [
        interface,
        (ticks >> 32) as u32,
        ticks as u32,
        data.len() as u32,
        wire,
    ] {
        result.extend(number(value, big));
    }
    result.extend(data);
    while result.len() % 4 != 0 {
        result.push(0);
    }
    result.extend(option(1, b"retained evidence", big));
    result.extend(option(0, &[], big));
    block(6, result, big)
}

fn read(bytes: &[u8]) -> Result<Vec<packrat_tui::net::packet::Packet>, String> {
    let path = std::env::temp_dir().join(format!("packrat-ng-{}.pcapng", rand::random::<u64>()));
    std::fs::write(&path, bytes).unwrap();
    let result = read_pcap(&path);
    std::fs::remove_file(path).unwrap();
    result
}

#[test]
fn mixed_endian_sections_keep_exact_timestamps_interfaces_and_comments() {
    let mut bytes = section(false, 9, -1, 1);
    bytes.extend(enhanced(false, 0, 2_123_456_789, &[0; 14], 100));
    bytes.extend(section(true, 0x80 | 10, -2, 1));
    bytes.extend(enhanced(true, 0, 1536, &[0; 14], 14));
    let packets = read(&bytes).unwrap();
    let first = packets[0].capture.as_ref().unwrap();
    assert_eq!(first.timestamp.unwrap().nanoseconds(), 1_123_456_789);
    assert_eq!(first.interface_name.as_deref(), Some("sensor0"));
    assert_eq!(first.comments, ["retained evidence"]);
    assert!(first.truncated());
    let second = packets[1].capture.as_ref().unwrap();
    assert_eq!(second.section_id, 1);
    assert_eq!(second.timestamp.unwrap().nanoseconds(), -500_000_000);
}

#[test]
fn simple_packets_have_no_fabricated_timestamp_or_padding_bytes() {
    let mut bytes = section(false, 6, 0, 101);
    let mut simple = number(3, false).to_vec();
    simple.extend([0x45, 1, 2, 0]);
    bytes.extend(block(3, simple, false));
    let packets = read(&bytes).unwrap();
    assert_eq!(packets[0].bytes, [0x45, 1, 2]);
    assert!(packets[0].capture.as_ref().unwrap().timestamp.is_none());
    assert_eq!(packets[0].capture.as_ref().unwrap().link_type, 101);
    assert_eq!(packets[0].protocol, "RAW");
    let mut app = packrat_tui::app::App::new_for_test();
    app.inject_packet(packets[0].clone());
    assert_eq!(app.packets.len(), 1);
    assert!(app.flow_tracker.flows.is_empty());
    let fields = packrat_tui::analysis::packet_fields::extract_fields(&packets[0]);
    assert_eq!(
        fields
            .iter()
            .find(|field| field.path == "frame.time")
            .unwrap()
            .value,
        "Unavailable"
    );
    assert!(!fields.iter().any(|field| field.path.starts_with("tcp.")));
}

#[test]
fn invalid_interfaces_wire_lengths_and_truncated_blocks_are_rejected() {
    let base = section(false, 6, 0, 1);
    let mut invalid_interface = base.clone();
    invalid_interface.extend(enhanced(false, 1, 0, &[0; 14], 14));
    assert!(read(&invalid_interface).unwrap_err().contains("interface"));
    let mut invalid_length = base.clone();
    invalid_length.extend(enhanced(false, 0, 0, &[0; 14], 1));
    assert!(read(&invalid_length).unwrap_err().contains("length"));
    let mut truncated = base;
    truncated.extend(enhanced(false, 0, 0, &[0; 14], 14));
    truncated.pop();
    assert!(read(&truncated).is_err());
}

#[test]
fn every_truncated_prefix_is_handled_without_panicking() {
    let mut bytes = section(false, 9, 0, 1);
    bytes.extend(enhanced(false, 0, 123, &[0; 14], 14));
    for length in 0..bytes.len() {
        assert!(read(&bytes[..length]).is_err(), "prefix {length}");
    }
}
