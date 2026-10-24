#[cfg(feature = "real-capture")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use packrat_tui::net::packet::{CaptureMetadata, CaptureTimestamp, TimestampResolution};
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut interface = None;
    let mut filter = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--interface" => { index += 1; interface = args.get(index).cloned(); }
            "--filter" => { index += 1; filter = args.get(index).cloned(); }
            unknown => return Err(format!("unknown argument: {unknown}").into()),
        }
        index += 1;
    }
    let interface = interface.ok_or("--interface is required")?;
    let mut capture = pcap::Capture::from_device(interface.as_str())?
        .promisc(true).snaplen(65_535).timeout(100).open()?;
    if let Some(filter) = filter { capture.filter(&filter, true)?; }
    let mut capture = capture.setnonblock()?;
    let link_type = u32::try_from(capture.get_datalink().0)?;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    loop {
        let packet = match capture.next_packet() {
            Ok(packet) => packet,
            Err(pcap::Error::TimeoutExpired | pcap::Error::NoMorePackets) => {
                std::thread::sleep(std::time::Duration::from_millis(2));
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let fraction = u64::try_from(packet.header.ts.tv_usec)?;
        if fraction >= 1_000_000 { return Err("Invalid capture timestamp fraction".into()); }
        let metadata = CaptureMetadata {
            timestamp: Some(CaptureTimestamp { ticks: fraction, resolution: TimestampResolution::Decimal(6), offset_seconds: packet.header.ts.tv_sec as i64 }),
            captured_length: packet.header.caplen,
            wire_length: packet.header.len,
            link_type,
            interface_id: 0,
            section_id: 0,
            interface_name: None,
            comments: Vec::new(),
        };
        packrat_tui::capture::helper::write_capture_frame(&mut output, &metadata, packet.data)?;
    }
}

#[cfg(not(feature = "real-capture"))]
fn main() {
    eprintln!("packrat-capture-helper requires --features real-capture");
    std::process::exit(2);
}
