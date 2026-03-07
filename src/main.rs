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
mod dynamic;
mod event;
mod export;
mod filter;
mod net;
mod strings;
mod tabs;
mod topology;
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
        terminal.draw(|f| ui::draw(f, app))?;

        tokio::select! {
            _ = tick_interval.tick() => {
                app.tick();
            }
            Some(pkt) = packet_rx.recv() => {
                app.ingest_packet(pkt);
            }
            Some(Ok(evt)) = event_reader.next() => {
                if event::handle(app, evt) {
                    break;
                }
            }
        }
    }
    Ok(())
}
