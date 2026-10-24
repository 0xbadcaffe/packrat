use packrat_tui::storage::packet_archive::PacketArchive;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let Some(path) = args
        .next()
        .filter(|value| value != "--help" && value != "-h")
    else {
        println!(
            "Usage: packrat-archive DIRECTORY [PACKET_ID]\nShow archive packet count or recover one indexed packet as JSON."
        );
        return Ok(());
    };
    if !std::path::Path::new(&path).join("index.sqlite").is_file() {
        return Err("Archive does not exist".into());
    }
    let mut archive = PacketArchive::open_readonly(std::path::Path::new(&path))?;
    match args.next() {
        Some(id) => println!(
            "{}",
            serde_json::to_string_pretty(&archive.packet(id.parse()?)?)?
        ),
        None => println!("{} packets", archive.count()?),
    }
    Ok(())
}
