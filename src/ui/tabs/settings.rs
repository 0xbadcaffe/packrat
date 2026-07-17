use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table, Wrap},
};

use crate::app::App;
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
        ("Alert assistance", app.alert_center.automation_mode.to_string()),
        ("Guard mode", app.traffic_latch.mode.to_string()),
        ("Guard block timeout", format!("{} seconds", app.traffic_latch.expires_seconds)),
        ("Guard active limit", app.traffic_latch.max_active_blocks.to_string()),
        ("Guard kill switch", if app.traffic_latch.emergency_stop { "ENGAGED".into() } else { "Ready".into() }),
    ];
    let rows = entries.into_iter().enumerate().map(|(index, (label, value))| {
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
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn preferences_render_at_compact_and_normal_sizes() {
        for (width, height) in [(60, 18), (96, 26)] {
            let backend = TestBackend::new(width, height);
            let mut terminal = Terminal::new(backend).unwrap();
            let app = App::new_for_test();
            terminal.draw(|frame| draw(frame, &app, frame.area())).unwrap();
            let output = terminal.backend().buffer().content.iter()
                .map(|cell| cell.symbol())
                .collect::<String>();
            assert!(output.contains("Preferences"));
            assert!(output.contains("Theme"));
            assert!(output.contains("Guard"));
        }
    }
}
