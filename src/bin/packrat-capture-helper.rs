#[cfg(feature = "real-capture")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    use std::time::Instant;
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
    let start = Instant::now();
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    while let Ok(packet) = capture.next_packet() {
        let micros = start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        packrat_tui::capture::helper::write_frame(&mut output, micros, packet.data)?;
    }
    output.flush()?;
    Ok(())
}

#[cfg(not(feature = "real-capture"))]
fn main() {
    eprintln!("packrat-capture-helper requires --features real-capture");
    std::process::exit(2);
}
