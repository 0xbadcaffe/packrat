#![allow(dead_code)]

use std::{io, time::Duration};

use anyhow::Result;
use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use futures::StreamExt;
use ratatui::{Terminal, backend::CrosstermBackend};
use tokio::time;

use packrat_tui::{analysis, app, event, storage, ui};

use app::{App, CliAction};
use packrat_tui::net::packet::Packet;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let options = match app::parse_startup_args(std::env::args().skip(1)) {
        Ok(CliAction::Run(options)) => options,
        Ok(CliAction::Help) => {
            println!("{}", app::usage());
            return Ok(());
        }
        Err(e) => {
            eprintln!("{e}\n\n{}", app::usage());
            std::process::exit(2);
        }
    };

    let telemetry_listener = match options.telemetry_listen {
        Some(address) => Some(analysis::telemetry::bind(address).await?),
        None => None,
    };
    if options.sandbox {
        let paths = analysis::runtime_guard::default_write_paths().map_err(anyhow::Error::msg)?;
        analysis::runtime_guard::apply(&paths).map_err(anyhow::Error::msg)?;
    }
    let packet_archive = options
        .archive_path
        .as_ref()
        .map(|path| {
            if options.archive_alert_evidence_only {
                storage::packet_archive::ArchiveWorker::open_alert_evidence(path, options.archive_limits)
            } else {
                storage::packet_archive::ArchiveWorker::open_with_limits(path, options.archive_limits)
            }
        })
        .transpose()
        .map_err(anyhow::Error::msg)?;

    let (packet_tx, mut packet_rx) = tokio::sync::mpsc::channel::<Packet>(10_000);
    let mut app = App::new_with_mode(packet_tx, options.mode);
    if let Some(archive) = packet_archive {
        app.set_packet_archive_with_rules(archive, options.archive_evidence_rules)
            .map_err(anyhow::Error::msg)?;
    }
    app.traffic_latch.mode = options.latch_mode;
    app.traffic_latch.expires_seconds = options.latch_expiry_seconds;
    app.traffic_latch.protected_addresses = options.protected_addresses;
    app.latch_helper_path = options.latch_helper_path;
    app.reputation_helper_path = options.reputation_helper_path;
    app.capture_helper_path = options.capture_helper_path;
    if let Some(path) = options.endpoint_evidence_path {
        match analysis::impact::read_endpoint_evidence(&path) {
            Ok(events) => app.configure_core(move |core| core.endpoint_evidence = events),
            Err(error) => app.set_status(format!("Endpoint evidence import failed: {error}")),
        }
    }
    app.configure_core(move |core| {
        core.vlan_intel.policy = options.vlan_policy;
        core.tls_tracker.decrypt_helper_path = options.tls_decrypt_helper_path;
        core.quic_scope.decode_helper_path = options.quic_decode_helper_path;
    });
    let key_log_path = options.key_log_path.or_else(|| {
        if options.project_path.is_some() { return None; }
        std::env::var_os("SSLKEYLOGFILE").map(Into::into)
    });
    if let Some(path) = key_log_path {
        app.load_key_log(path);
    }
    if let Some(path) = options.socket_events_path {
        match app.socket_scope.load_event_file(&path) {
            Ok(count) => app.set_status(format!("Imported {count} socket ownership events")),
            Err(error) => app.set_status(format!("Socket event import failed: {error}")),
        }
    }
    if let Some(listener) = telemetry_listener {
        tokio::spawn(analysis::telemetry::serve(listener, app.telemetry.clone()));
    }

    app.start_background_analysis().map_err(anyhow::Error::msg)?;
    if let Some(path) = options.project_path {
        app.open_project(&path).map_err(anyhow::Error::msg)?;
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    let mut tick_interval = time::interval(Duration::from_millis(100));
    let mut event_reader = crossterm::event::EventStream::new();
    let result = run_loop(&mut terminal, &mut app, &mut tick_interval, &mut packet_rx, &mut event_reader).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    let shutdown = app.stop_background_analysis();
    match &shutdown {
        Ok(0) => (),
        Ok(cancelled) => eprintln!("Shutdown cancelled {cancelled} pending analysis items."),
        Err(error) => eprintln!("{error}"),
    }
    if let Some(archive) = app.packet_archive.as_mut() {
        archive.finish().map_err(anyhow::Error::msg)?;
    }

    result.and(shutdown.map(|_| ()).map_err(anyhow::Error::msg))
}

async fn run_loop(
    terminal: &mut ratatui::Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    tick_interval: &mut time::Interval,
    packet_rx: &mut tokio::sync::mpsc::Receiver<Packet>,
    event_reader: &mut crossterm::event::EventStream,
) -> Result<()> {
    let mut pending_packet = None;
    let mut redraw_period = Duration::from_millis(app.ui_refresh_ms);
    let mut redraw_interval = time::interval(redraw_period);
    let mut redraw_pending = true;
    loop {
        if let Some(receiver) = app.take_capture_receiver() {
            *packet_rx = receiver;
            pending_packet = None;
        }
        let configured_period = Duration::from_millis(app.ui_refresh_ms);
        if configured_period != redraw_period {
            redraw_period = configured_period;
            redraw_interval = time::interval(redraw_period);
        }
        app.poll_analysis();
        app.dispatch_capture(packet_rx, &mut pending_packet)
            .map_err(anyhow::Error::msg)?;
        if redraw_pending {
            if let Some(view) = app.try_view().map_err(anyhow::Error::msg)? {
                terminal.draw(|f| ui::draw_view(f, &view))?;
            }
            redraw_pending = false;
        }

        let analysis_ready = app.analysis_event_notifier();
        tokio::select! {
            _ = async {
                match analysis_ready {
                    Some(ready) => ready.notified().await,
                    None => std::future::pending().await,
                }
            } => {}
            _ = tick_interval.tick() => {
                app.tick();
                redraw_pending = true;
            }
            _ = redraw_interval.tick() => {
                redraw_pending = true;
            }
            Some(Ok(evt)) = event_reader.next() => {
                if event::handle(app, evt) {
                    break;
                }
                redraw_pending = true;
            }
            // Also wake up when the first new packet arrives so the
            // next iteration can drain it without waiting a full tick.
            pkt = packet_rx.recv(), if pending_packet.is_none() && !app.analysis_backpressured() => {
                pending_packet = pkt;
            }
        }
    }
    Ok(())
}
