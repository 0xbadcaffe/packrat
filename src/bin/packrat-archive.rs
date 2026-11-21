use packrat_tui::storage::packet_archive::PacketArchive;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let Some(path) = args
        .next()
        .filter(|value| value != "--help" && value != "-h")
    else {
        println!(
            "Usage: packrat-archive DIRECTORY [PACKET_ID | --capture-frame CAPTURE_ID FRAME_NUMBER | --import CAPTURE | --export OUTPUT.pcapng | --host ADDRESS [AFTER_ID]]\n       packrat-archive DIRECTORY --alert-status ALERT_LOG SESSION_ID ALERT_ID [--capture-id CAPTURE_ID]\n       packrat-archive DIRECTORY --alert-evidence ALERT_LOG SESSION_ID ALERT_ID OUTPUT_DIR [--capture-id CAPTURE_ID]"
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
        Some(flag) if matches!(flag.as_str(), "--alert-evidence" | "--alert-status") => {
            use packrat_tui::storage::alert_evidence::{alert_evidence_availability, export_scoped_alert_evidence};
            let log = args.next().ok_or("Alert command requires an alert log")?;
            let session = args.next().ok_or("Alert command requires a session ID")?;
            let id = args.next().ok_or("Alert command requires an alert ID")?.parse()?;
            let output = if flag == "--alert-evidence" {
                Some(args.next().ok_or("--alert-evidence requires a new output directory")?)
            } else {
                None
            };
            let capture_filter = match args.next().as_deref() {
                Some("--capture-id") => Some(args.next().filter(|id| !id.is_empty()).ok_or("--capture-id requires a capture ID")?),
                Some(_) => return Err("Expected --capture-id after positional arguments".into()),
                None => None,
            };
            if args.next().is_some() {
                return Err("Unexpected argument after capture ID".into());
            }
            let log = std::path::Path::new(&log);
            let scope = capture_filter.as_deref();
            if let Some(output) = output {
                let summary = export_scoped_alert_evidence(
                    &mut archive, log, &session, id, scope, std::path::Path::new(&output),
                )?;
                println!("{}", serde_json::to_string(&summary)?);
            } else {
                let status = alert_evidence_availability(&mut archive, log, &session, id, scope)?;
                println!("{}", serde_json::to_string(&status)?);
            }
        }
        Some(flag) if flag == "--capture-frame" => {
            let capture_id = args.next().ok_or("--capture-frame requires a capture ID")?;
            let number = args.next().ok_or("--capture-frame requires a frame number")?.parse()?;
            if args.next().is_some() {
                return Err("Unexpected argument after frame number".into());
            }
            let packet = archive.packet_for_capture(&capture_id, number)?
                .ok_or("Frame not found in the specified capture")?;
            println!("{}", serde_json::to_string_pretty(&packet)?);
        }
        Some(id) => println!(
            "{}",
            serde_json::to_string_pretty(&archive.packet(id.parse()?)?)?
        ),
        None => println!("{} packets", archive.count()?),
    }
    Ok(())
}
