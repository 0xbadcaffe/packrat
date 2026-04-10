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

mod app;
mod capture;
mod craft;
mod dissector;
mod event;
mod export;
mod filter;
mod net;
mod pcap_replay;
mod scan;
mod sim;
mod tabs;
mod traceroute;
mod ui;

use app::App;
use net::packet::Packet;

#[tokio::main]
async fn main() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let (packet_tx, mut packet_rx) = tokio::sync::mpsc::channel::<Packet>(10_000);
    let mut app = App::new(packet_tx);

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
