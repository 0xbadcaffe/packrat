use packrat_tui::storage::packet_archive::PacketArchive;
use packrat_tui::storage::alert_history::{AlertLogs, MAX_PREVIOUS_LOGS};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let Some(path) = args
        .next()
        .filter(|value| value != "--help" && value != "-h")
    else {
        println!(
            "Usage: packrat-archive DIRECTORY [PACKET_ID | --capture-frame CAPTURE_ID FRAME_NUMBER | --import CAPTURE | --export OUTPUT.pcapng | --host ADDRESS [AFTER_ID]]\n       packrat-archive --alerts ALERT_LOG [--previous-log PATH]... [--session SESSION_ID] [--capture-id CAPTURE_ID] [--limit COUNT] [--report-integrity]\n       packrat-archive DIRECTORY --alert-status ALERT_LOG SESSION_ID ALERT_ID [--capture-id CAPTURE_ID] [--previous-log PATH]...\n       packrat-archive DIRECTORY --alert-evidence ALERT_LOG SESSION_ID ALERT_ID OUTPUT_DIR [--capture-id CAPTURE_ID] [--previous-log PATH]...\n       packrat-archive --project-alert-status PROJECT ALERT_LOG SESSION_ID CAPTURE_ID ALERT_ID [--previous-log PATH]...\n       packrat-archive --project-alert-evidence PROJECT ALERT_LOG SESSION_ID CAPTURE_ID ALERT_ID OUTPUT_DIR [--previous-log PATH]...\n       packrat-archive --verify-evidence EVIDENCE_DIR\nList previous alert logs oldest first. Integrity counts describe only the records examined."
        );
        return Ok(());
    };
    if path == "--alerts" {
        return list_alerts(args);
    }
    if matches!(path.as_str(), "--project-alert-status" | "--project-alert-evidence") {
        return project_alert(args, path == "--project-alert-evidence");
    }
    if path == "--verify-evidence" {
        let directory = args.next().ok_or("--verify-evidence requires an evidence directory")?;
        if args.next().is_some() {
            return Err("Unexpected argument after evidence directory".into());
        }
        let summary = packrat_tui::storage::alert_evidence::verify_alert_evidence(std::path::Path::new(&directory))?;
        println!("{}", serde_json::to_string(&summary)?);
        return Ok(());
    }
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
            use packrat_tui::storage::alert_evidence::{alert_evidence_across_logs, export_alert_evidence_across_logs};
            let log = args.next().ok_or("Alert command requires an alert log")?;
            let session = args.next().ok_or("Alert command requires a session ID")?;
            let id = args.next().ok_or("Alert command requires an alert ID")?.parse()?;
            let output = if flag == "--alert-evidence" {
                Some(args.next().ok_or("--alert-evidence requires a new output directory")?)
            } else {
                None
            };
            let mut capture_filter = None;
            let mut previous = Vec::new();
            while let Some(option) = args.next() {
                let value = args.next().filter(|value| !value.is_empty() && !value.starts_with("--"))
                    .ok_or_else(|| format!("{option} requires a value"))?;
                match option.as_str() {
                    "--capture-id" if capture_filter.is_none() => capture_filter = Some(value),
                    "--previous-log" if previous.len() < MAX_PREVIOUS_LOGS => previous.push(PathBuf::from(value)),
                    "--previous-log" => return Err("Too many previous alert logs".into()),
                    _ => return Err(format!("Unknown or repeated alert option: {option}").into()),
                }
            }
            let logs = AlertLogs::new(std::path::Path::new(&log), &previous)?;
            let scope = capture_filter.as_deref();
            if let Some(output) = output {
                let summary = export_alert_evidence_across_logs(
                    &mut archive, logs, &session, id, scope, std::path::Path::new(&output),
                )?;
                println!("{}", serde_json::to_string(&summary)?);
            } else {
                let status = alert_evidence_across_logs(&mut archive, logs, &session, id, scope)?;
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

fn project_alert(
    mut args: impl Iterator<Item = String>,
    export: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use packrat_tui::storage::alert_evidence::{export_project_alert_evidence, project_alert_evidence};
    use std::path::Path;

    let project = args.next().ok_or("Project alert status requires a project path")?;
    let log = args.next().ok_or("Project alert status requires an alert log")?;
    let session = args.next().ok_or("Project alert status requires a session ID")?;
    let capture = args.next().ok_or("Project alert status requires a capture ID")?;
    let id = args.next().ok_or("Project alert status requires an alert ID")?.parse()?;
    let output = if export {
        Some(args.next().ok_or("--project-alert-evidence requires a new output directory")?)
    } else {
        None
    };
    let mut previous = Vec::new();
    while let Some(flag) = args.next() {
        if flag != "--previous-log" || previous.len() == MAX_PREVIOUS_LOGS {
            return Err(format!("Unexpected or excessive project alert option: {flag}").into());
        }
        let value = args.next().filter(|value| !value.is_empty() && !value.starts_with("--"))
            .ok_or("--previous-log requires a value")?;
        previous.push(PathBuf::from(value));
    }
    let logs = AlertLogs::new(Path::new(&log), &previous)?;
    let project = Path::new(&project);
    if let Some(output) = output {
        let summary = export_project_alert_evidence(project, logs, &session, id, &capture, Path::new(&output))?;
        println!("{}", serde_json::to_string(&summary)?);
    } else {
        let status = project_alert_evidence(project, logs, &session, id, &capture)?;
        println!("{}", serde_json::to_string(&status)?);
    }
    Ok(())
}

fn list_alerts(mut args: impl Iterator<Item = String>) -> Result<(), Box<dyn std::error::Error>> {
    use packrat_tui::storage::alert_history::recent_alerts_report;

    let log = args.next().ok_or("--alerts requires an alert log")?;
    let (mut session, mut capture, mut limit) = (None, None, None);
    let mut previous = Vec::new();
    let mut report_integrity = false;
    while let Some(flag) = args.next() {
        if flag == "--report-integrity" && !report_integrity {
            report_integrity = true;
            continue;
        }
        let value = args.next().filter(|value| !value.is_empty() && !value.starts_with("--"))
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match flag.as_str() {
            "--session" if session.is_none() => session = Some(value),
            "--capture-id" if capture.is_none() => capture = Some(value),
            "--limit" if limit.is_none() => limit = Some(value.parse()?),
            "--previous-log" if previous.len() < MAX_PREVIOUS_LOGS => previous.push(PathBuf::from(value)),
            "--previous-log" => return Err("Too many previous alert logs".into()),
            _ => return Err(format!("Unknown or repeated alert option: {flag}").into()),
        }
    }
    let report = recent_alerts_report(
        &previous, std::path::Path::new(&log), session.as_deref(), capture.as_deref(), limit.unwrap_or(50),
    )?;
    if report_integrity {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!("{}", serde_json::to_string(&report.alerts)?);
    }
    Ok(())
}
