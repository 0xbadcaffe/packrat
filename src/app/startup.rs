use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupMode {
    Capture,
    Simulation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliAction {
    Run(StartupOptions),
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupOptions {
    pub mode: StartupMode,
    pub telemetry_listen: Option<std::net::SocketAddr>,
    pub key_log_path: Option<std::path::PathBuf>,
    pub tls_decrypt_helper_path: Option<std::path::PathBuf>,
    pub quic_decode_helper_path: Option<std::path::PathBuf>,
    pub latch_mode: LatchMode,
    pub latch_expiry_seconds: u64,
    pub protected_addresses: Vec<std::net::IpAddr>,
    pub sandbox: bool,
    pub socket_events_path: Option<std::path::PathBuf>,
    pub latch_helper_path: Option<std::path::PathBuf>,
    pub reputation_helper_path: Option<std::path::PathBuf>,
    pub capture_helper_path: Option<std::path::PathBuf>,
    pub endpoint_evidence_path: Option<std::path::PathBuf>,
    pub archive_path: Option<std::path::PathBuf>,
}

pub fn usage() -> String {
    let endpoint_help =
        "      --endpoint-evidence PATH import endpoint impact evidence as NDJSON\n";
    let base = usage_base();
    base.replace("      --socket-events", &format!("{endpoint_help}      --archive PATH           retain packets and SQLite index in directory\n      --socket-events"))
}

pub(super) fn usage_base() -> &'static str {
    "Usage: packrat [OPTIONS]\n\nOptions:\n  -s, --simulation           run the built-in simulated traffic scenario\n      --key-log PATH         load NSS/SSLKEYLOGFILE TLS and QUIC secrets\n      --tls-decrypt-helper P delegate authenticated TLS record decode to helper\n      --quic-decode-helper P delegate protected QUIC/HTTP3 decode to helper\n      --socket-events PATH   import socket ownership CSV from an external helper\n      --capture-helper PATH  delegate packet capture to a privileged helper\n      --latch-helper PATH    delegate TrafficLatch blocks to a JSON helper command\n      --reputation-helper P  delegate explicit reputation refreshes to a helper\n      --telemetry-listen A   expose /metrics and /health (example: 127.0.0.1:9477)\n      --traffic-latch MODE   monitor, preview, manual, or auto (default: monitor)\n      --latch-seconds N      automatic firewall expiry (default: 900)\n      --protect-address IP   never contain this address; may be repeated\n      --sandbox              restrict filesystem writes with Linux Landlock\n  -h, --help                 show this help"
}

pub fn parse_startup_args<I, S>(args: I) -> Result<CliAction, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args
        .into_iter()
        .map(|arg| arg.as_ref().to_string())
        .collect();
    let mut options = StartupOptions {
        mode: StartupMode::Capture,
        telemetry_listen: None,
        key_log_path: None,
        tls_decrypt_helper_path: None,
        quic_decode_helper_path: None,
        latch_mode: LatchMode::Monitor,
        latch_expiry_seconds: 900,
        protected_addresses: Vec::new(),
        sandbox: false,
        socket_events_path: None,
        latch_helper_path: None,
        reputation_helper_path: None,
        capture_helper_path: None,
        endpoint_evidence_path: None,
        archive_path: None,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--archive" => {
                index += 1;
                let value = args.get(index).ok_or("--archive requires a directory")?;
                options.archive_path = Some(value.into());
            }
            "--endpoint-evidence" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or("--endpoint-evidence requires an NDJSON path")?;
                options.endpoint_evidence_path = Some(value.into());
            }
            "-s" | "--simulation" => options.mode = StartupMode::Simulation,
            "-h" | "--help" => return Ok(CliAction::Help),
            "--telemetry-listen" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or("--telemetry-listen requires an address")?;
                options.telemetry_listen = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid telemetry address: {value}"))?,
                );
            }
            "--key-log" => {
                index += 1;
                let value = args.get(index).ok_or("--key-log requires a path")?;
                options.key_log_path = Some(value.into());
            }
            "--tls-decrypt-helper" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or("--tls-decrypt-helper requires a path")?;
                options.tls_decrypt_helper_path = Some(value.into());
            }
            "--quic-decode-helper" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or("--quic-decode-helper requires a path")?;
                options.quic_decode_helper_path = Some(value.into());
            }
            "--socket-events" => {
                index += 1;
                let value = args.get(index).ok_or("--socket-events requires a path")?;
                options.socket_events_path = Some(value.into());
            }
            "--capture-helper" => {
                index += 1;
                let value = args.get(index).ok_or("--capture-helper requires a path")?;
                options.capture_helper_path = Some(value.into());
            }
            "--latch-helper" => {
                index += 1;
                let value = args.get(index).ok_or("--latch-helper requires a path")?;
                options.latch_helper_path = Some(value.into());
            }
            "--reputation-helper" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or("--reputation-helper requires a path")?;
                options.reputation_helper_path = Some(value.into());
            }
            "--traffic-latch" => {
                index += 1;
                let value = args.get(index).ok_or("--traffic-latch requires a mode")?;
                options.latch_mode = value.parse()?;
            }
            "--latch-seconds" => {
                index += 1;
                let value = args.get(index).ok_or("--latch-seconds requires a value")?;
                options.latch_expiry_seconds = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid latch expiry: {value}"))?;
                if !(10..=86_400).contains(&options.latch_expiry_seconds) {
                    return Err("latch expiry must be between 10 and 86400 seconds".into());
                }
            }
            "--protect-address" => {
                index += 1;
                let value = args.get(index).ok_or("--protect-address requires an IP")?;
                options.protected_addresses.push(
                    value
                        .parse()
                        .map_err(|_| format!("invalid protected address: {value}"))?,
                );
            }
            "--sandbox" => options.sandbox = true,
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
        index += 1;
    }
    Ok(CliAction::Run(options))
}

pub(super) fn list_interfaces(include_simulated: bool) -> Vec<String> {
    let mut ifaces = Vec::new();
    if include_simulated {
        ifaces.push("simulated".to_string());
    }
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        let mut sys: Vec<String> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        sys.sort();
        ifaces.extend(sys);
    }
    ifaces
}
