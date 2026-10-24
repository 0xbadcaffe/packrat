#[cfg(feature = "real-capture")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    if capture.get_datalink() != pcap::Linktype::ETHERNET {
        return Err("Only Ethernet capture link types are currently supported".into());
    }
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
        let seconds = u64::try_from(packet.header.ts.tv_sec)?;
        let fraction = u64::try_from(packet.header.ts.tv_usec)?;
        let micros = seconds.checked_mul(1_000_000).and_then(|value| value.checked_add(fraction)).ok_or("Capture timestamp overflow")?;
        packrat_tui::capture::helper::write_frame(&mut output, micros, packet.data)?;
    }
}

#[cfg(not(feature = "real-capture"))]
fn main() {
    eprintln!("packrat-capture-helper requires --features real-capture");
    std::process::exit(2);
}
