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
    #[cfg(feature = "terminal-ui")]
    {
        let mut app = packrat_tui::app::App::new_for_test();
        app.inject_packet(packets[0].clone());
        assert_eq!(app.packets.len(), 1);
        assert!(app.core.read().unwrap().flow_tracker.flows.is_empty());
    }
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

#[test]
fn export_round_trip_preserves_raw_bytes_clocks_names_comments_and_wire_lengths() {
    let mut bytes = section(false, 0x80 | 10, -3, 1);
    bytes.extend(enhanced(false, 0, 1536, &[1; 17], 100));
    bytes.extend(section(true, 9, 0, 101));
    bytes.extend(enhanced(true, 0, 123456789, &[0x45; 23], 25));
    let original = read(&bytes).unwrap();
    let mut output = Vec::new();
    {
        let mut writer = packrat_tui::export::pcapng::PcapNgWriter::new(&mut output);
        for packet in &original { writer.write_packet(packet).unwrap(); }
        writer.flush().unwrap();
    }
    let restored = read(&output).unwrap();
    for (left, right) in original.iter().zip(restored.iter()) {
        assert_eq!(left.bytes, right.bytes);
        assert_eq!(left.capture, right.capture);
    }
}

#[test]
fn export_untimed_packets_do_not_fabricate_times_or_include_padding() {
    let mut bytes = section(false, 6, 0, 101);
    let mut simple = number(8, false).to_vec();
    simple.extend([0x45; 8]);
    bytes.extend(block(3, simple, false));
    let mut original = read(&bytes).unwrap().remove(0);
    original.bytes.truncate(3);
    original.capture.as_mut().unwrap().captured_length = 3;
    let mut output = Vec::new();
    {
        let mut writer = packrat_tui::export::pcapng::PcapNgWriter::new(&mut output);
        writer.write_packet(&original).unwrap();
        writer.write_packet(&original).unwrap();
        writer.flush().unwrap();
    }
    for restored in read(&output).unwrap() {
        let capture = restored.capture.unwrap();
        assert!(capture.timestamp.is_none());
        assert_eq!(capture.wire_length, 8);
        assert_eq!(capture.link_type, 101);
        assert_eq!(restored.bytes, [0x45; 3]);
    }
}

#[test]
fn export_validation_fails_before_writing_invalid_packets() {
    use packrat_tui::net::packet::TimestampResolution;
    let mut bytes = section(false, 9, 0, 1);
    bytes.extend(enhanced(false, 0, 10, &[1; 14], 14));
    let original = read(&bytes).unwrap().remove(0);
    for variant in 0..6 {
        let mut packet = original.clone();
        let metadata = packet.capture.as_mut().unwrap();
        match variant {
            0 => metadata.captured_length += 1,
            1 => metadata.wire_length = 0,
            2 => metadata.timestamp.as_mut().unwrap().resolution = TimestampResolution::Decimal(128),
            3 => metadata.link_type = 65536,
            4 => metadata.comments.push("x".repeat(4097)),
            _ => metadata.timestamp = None,
        }
        let mut output = Vec::new();
        let mut writer = packrat_tui::export::pcapng::PcapNgWriter::new(&mut output);
        assert!(writer.write_packet(&packet).is_err(), "variant {variant}");
        assert!(output.is_empty());
    }
}

#[test]
fn export_io_errors_are_returned_and_existing_files_never_overwritten() {
    struct Fail;
    impl std::io::Write for Fail {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disk full"))
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    let packet = packrat_tui::net::parser::parse_ethernet(&[0; 14], 1, 1.0);
    let mut writer = packrat_tui::export::pcapng::PcapNgWriter::new(Fail);
    assert!(writer.write_packet(&packet).unwrap_err().to_string().contains("disk full"));
    let path = std::env::temp_dir().join(format!("packrat-export-{}.pcapng", rand::random::<u64>()));
    std::fs::write(&path, "original").unwrap();
    assert!(packrat_tui::export::pcapng::PcapNgWriter::create(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"original");
    std::fs::remove_file(path).unwrap();
}

#[test]
fn archive_cli_streams_export_and_reimport_with_metadata() {
    let directory = std::env::temp_dir().join(format!("packrat-export-{}", rand::random::<u64>()));
    let output = directory.join("evidence.pcapng");
    let mut bytes = section(false, 9, -1, 101);
    bytes.extend(enhanced(false, 0, 2_123_456_789, &[0x45; 14], 100));
    let packets = read(&bytes).unwrap();
    {
        let mut archive = packrat_tui::storage::packet_archive::PacketArchive::open(&directory).unwrap();
        archive.append(&packets).unwrap();
    }
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
        .arg(&directory).arg("--export").arg(&output).output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert_eq!(String::from_utf8_lossy(&result.stdout).trim(), "Exported 1 packets");
    let restored = read_pcap(&output).unwrap();
    assert_eq!(restored[0].bytes, packets[0].bytes);
    assert_eq!(restored[0].capture, packets[0].capture);
    std::fs::remove_dir_all(directory).unwrap();
}
