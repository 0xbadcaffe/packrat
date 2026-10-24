use packrat_tui::storage::packet_archive::PacketArchive;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let Some(path) = args
        .next()
        .filter(|value| value != "--help" && value != "-h")
    else {
        println!(
            "Usage: packrat-archive DIRECTORY [PACKET_ID | --import CAPTURE | --export OUTPUT.pcapng | --host ADDRESS [AFTER_ID]]\nShow archive packet count, recover a packet as JSON, import/export a capture, or find up to 1000 retained packet IDs."
        );
        return Ok(());
    };
    let action = args.next();
    if action.as_deref() == Some("--import") {
        let input = args.next().ok_or("--import requires a capture path")?;
        let mut archive = PacketArchive::open(std::path::Path::new(&path))?;
        let mut batch = Vec::with_capacity(256);
        let count = packrat_tui::pcap_replay::stream_pcap(std::path::Path::new(&input), |packet| {
            batch.push(packet);
            if batch.len() == 256 {
                archive.append(&batch)?;
                batch.clear();
            }
            Ok(())
        })?;
        archive.append(&batch)?;
        println!("Imported {count} packets");
        return Ok(());
    }
    if !std::path::Path::new(&path).join("index.sqlite").is_file() {
        return Err("Archive does not exist".into());
    }
    let mut archive = PacketArchive::open_readonly(std::path::Path::new(&path))?;
    if action.as_deref() == Some("--export") {
        let output = args.next().ok_or("--export requires a new output path")?;
        let mut writer = packrat_tui::export::pcapng::PcapNgWriter::create(std::path::Path::new(&output))?;
        let mut after = 0;
        let mut count = 0u64;
        loop {
            let ids = archive.packet_ids(after, 256)?;
            if ids.is_empty() { break; }
            for id in ids {
                writer.write_packet(&archive.packet(id)?)?;
                after = id;
                count += 1;
            }
        }
        writer.flush()?;
        println!("Exported {count} packets");
        return Ok(());
    }
    if action.as_deref() == Some("--host") {
        let address = args.next().ok_or("--host requires an address")?;
        let after = args.next().map(|value| value.parse::<i64>()).transpose()?.unwrap_or(0);
        println!("{}", serde_json::to_string(&archive.find_host(&address, after, 1000)?)?);
        return Ok(());
    }
    match action {
        Some(id) => println!(
            "{}",
            serde_json::to_string_pretty(&archive.packet(id.parse()?)?)?
        ),
        None => println!("{} packets", archive.count()?),
    }
    Ok(())
}
