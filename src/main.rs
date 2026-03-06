use std::{
    io,
    time::{Duration, Instant},
};

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    Terminal,
};

mod app;
mod packet;
mod ui;
mod strings;
mod dynamic;
mod capture;

use app::{App, Tab};

fn main() -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let tick_rate = Duration::from_millis(100);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| ui::draw(f, &mut app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_default();

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                // Always allow quit
                if key.code == KeyCode::Char('q')
                    || (key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL)
                {
                    break;
                }

                if app.picking_iface {
                    match key.code {
                        KeyCode::Down | KeyCode::Char('j') => app.iface_down(),
                        KeyCode::Up   | KeyCode::Char('k') => app.iface_up(),
                        KeyCode::Char(' ') | KeyCode::Enter => app.confirm_iface(),
                        _ => {}
                    }
                } else {
                    match key.code {
                        // Tab switching
                        KeyCode::Char('1') => app.active_tab = Tab::Packets,
                        KeyCode::Char('2') => app.active_tab = Tab::Analysis,
                        KeyCode::Char('3') => app.active_tab = Tab::Strings,
                        KeyCode::Char('4') => app.active_tab = Tab::Dynamic,
                        KeyCode::Char('5') => app.active_tab = Tab::Visualize,
                        KeyCode::Tab => app.next_tab(),

                        // Navigation
                        KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                        KeyCode::Up   | KeyCode::Char('k') => app.move_up(),
                        KeyCode::Char('g') => app.move_top(),
                        KeyCode::Char('G') => app.move_bottom(),
                        KeyCode::PageDown  => app.page_down(),
                        KeyCode::PageUp    => app.page_up(),

                        // Capture control
                        KeyCode::Char(' ') => app.toggle_capture(),
                        KeyCode::Char('C') => app.clear_packets(),

                        // Filter
                        KeyCode::Char('/') => app.toggle_filter_mode(),
                        KeyCode::Esc => app.filter_mode = false,
                        KeyCode::Enter if app.filter_mode => {
                            app.filter_mode = false;
                            app.apply_filter();
                        }
                        KeyCode::Backspace if app.filter_mode => {
                            app.filter_input.pop();
                            app.apply_filter();
                        }
                        KeyCode::Char(c) if app.filter_mode => {
                            app.filter_input.push(c);
                            app.apply_filter();
                        }

                        _ => {}
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.tick();
            last_tick = Instant::now();
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}
