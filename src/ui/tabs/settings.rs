use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table, Wrap},
};

use crate::app::AppView as App;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(7)])
        .split(area);

    let entries = [
        ("Theme", app.selected_theme_name.clone()),
        ("Follow new packets", on_off(app.auto_scroll)),
        ("Startup workspace", app.preferred_workspace.label().into()),
        ("Alert assistance", app.core.alert_center.automation_mode.to_string()),
        ("Guard mode", app.traffic_latch.mode.to_string()),
        ("Guard block timeout", format!("{} seconds", app.traffic_latch.expires_seconds)),
        ("Guard active limit", app.traffic_latch.max_active_blocks.to_string()),
        ("Guard kill switch", if app.traffic_latch.emergency_stop { "ENGAGED".into() } else { "Ready".into() }),
        ("UI refresh interval", format!("{} ms ({} FPS)", app.ui_refresh_ms, 1_000 / app.ui_refresh_ms)),
        ("Capture read timeout", format!("{} ms", app.capture_timeout_ms)),
        ("Save alerts as JSONL", on_off(app.save_alerts)),
    ];
    let visible_rows = chunks[0].height.saturating_sub(3).max(1) as usize;
    let first_row = app.settings_cursor.saturating_add(1).saturating_sub(visible_rows);
    let rows = entries.into_iter().enumerate().skip(first_row).take(visible_rows).map(|(index, (label, value))| {
        let selected = app.settings_cursor == index;
        let style = if selected {
            Style::default().fg(C_BG()).bg(C_CYAN()).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_FG())
        };
        Row::new([
            Cell::from(if selected { format!("> {label}") } else { format!("  {label}") }),
            Cell::from(value),
        ]).style(style)
    });
    let table = Table::new(rows, [Constraint::Percentage(50), Constraint::Percentage(50)])
        .header(Row::new(["Preference", "Current value"]).style(
            Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
        ))
        .block(panel("Preferences"))
        .style(Style::default().bg(C_BG()));
    f.render_widget(table, chunks[0]);

    let detail = setting_detail(app);
    let footer = Paragraph::new(vec![
        Line::from(Span::styled(detail, Style::default().fg(C_FG2()))),
        Line::raw(""),
        Line::from(vec![
            Span::styled("j/k", key()), Span::raw(" select   "),
            Span::styled("Left/Right", key()), Span::raw(" change   "),
            Span::styled("Enter", key()), Span::raw(" edit/toggle   "),
            Span::styled("Esc", key()), Span::raw(" close"),
        ]),
    ]).block(panel("Selected Setting")).wrap(Wrap { trim: true });
    f.render_widget(footer, chunks[1]);
}

fn setting_detail(app: &App) -> String {
    match app.settings_cursor {
        0 => "Open the theme gallery. Theme changes are applied immediately and saved globally.".into(),
        1 => "Keep the packet cursor on the newest matching packet while traffic arrives.".into(),
        2 => "Choose the workspace Packrat opens on the next launch.".into(),
        3 => "Off is manual. Watch pins urgent findings. Triage also adds deterministic priorities and advice.".into(),
        4 => "Monitor and preview do not alter the firewall. Manual and automatic modes require Guard policy gates.".into(),
        5 => "Set the expiry for newly applied firewall blocks. Range: 60 seconds to 24 hours.".into(),
        6 => format!("Limit concurrent, unexpired blocks. Currently active: {}.", app.traffic_latch.active_count()),
        8 => "Set the redraw interval. Lower values make the interface smoother and use more CPU. Range: 20–250 ms.".into(),
        9 => "Set the blocking capture read timeout. It also bounds how long capture may take to notice a stop request. Range: 25–1000 ms; applies to the next capture start.".into(),
        10 => "Append versioned Alert Center records to the JSONL file in Packrat's data directory. Existing alerts are not backfilled.".into(),
        _ if app.traffic_latch.emergency_stop => "Reset the emergency stop. Guard remains in monitor mode after reset.".into(),
        _ => "The emergency stop is ready. Press ! globally to revoke active blocks and force monitor mode.".into(),
    }
}

fn on_off(value: bool) -> String {
    if value { "On".into() } else { "Off".into() }
}

fn key() -> Style {
    Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD)
}

fn panel(title: &'static str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(C_BORDER()))
        .title(Span::styled(format!(" {title} "), Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)))
        .style(Style::default().bg(C_BG()))
}

#[cfg(test)]
#[path = "../../../tests/unit/ui_tabs_settings_tests.rs"]
mod tests;
