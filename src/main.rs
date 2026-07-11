#![allow(dead_code)]

use std::{io, time::Duration};

use anyhow::Result;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::StreamExt;
use ratatui::{backend::CrosstermBackend, Terminal};
use tokio::time;

mod analysis;
mod app;
mod capture;
mod craft;
mod dissector;
mod event;
mod export;
mod filter;
mod model;
mod net;
mod pcap_replay;
mod scan;
mod sim;
mod storage;
mod tabs;
mod traceroute;
mod ui;

use app::{App, CliAction};
use net::packet::Packet;

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
        let paths = analysis::runtime_guard::default_write_paths()
            .map_err(anyhow::Error::msg)?;
        analysis::runtime_guard::apply(&paths).map_err(anyhow::Error::msg)?;
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let (packet_tx, mut packet_rx) = tokio::sync::mpsc::channel::<Packet>(10_000);
    let mut app = App::new_with_mode(packet_tx, options.mode);
    app.traffic_latch.mode = options.latch_mode;
    app.traffic_latch.expires_seconds = options.latch_expiry_seconds;
    app.traffic_latch.protected_addresses = options.protected_addresses;
    if let Some(path) = options
        .key_log_path
        .or_else(|| std::env::var_os("SSLKEYLOGFILE").map(Into::into))
    {
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

    let mut tick_interval = time::interval(Duration::from_millis(100));
    let mut event_reader = crossterm::event::EventStream::new();

    let result = run_loop(&mut terminal, &mut app, &mut tick_interval, &mut packet_rx, &mut event_reader).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

async fn run_loop(
    terminal: &mut ratatui::Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    tick_interval: &mut time::Interval,
    packet_rx: &mut tokio::sync::mpsc::Receiver<Packet>,
    event_reader: &mut crossterm::event::EventStream,
) -> Result<()> {
    loop {
        // Drain every packet already queued — non-blocking so tick never starves.
        while let Ok(pkt) = packet_rx.try_recv() {
            app.ingest_packet(pkt);
        }

        terminal.draw(|f| ui::draw(f, app))?;

        tokio::select! {
            _ = tick_interval.tick() => {
                app.tick();
            }
            Some(Ok(evt)) = event_reader.next() => {
                if event::handle(app, evt) {
                    break;
                }
            }
            // Also wake up when the first new packet arrives so the
            // next iteration can drain it without waiting a full tick.
            pkt = packet_rx.recv() => {
                if let Some(p) = pkt { app.ingest_packet(p); }
            }
        }
    }
    Ok(())
}
