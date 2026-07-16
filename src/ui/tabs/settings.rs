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
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(24), Constraint::Min(0)])
        .split(area);
    draw_sections(f, app, chunks[0]);
    draw_details(f, app, chunks[1]);
}

fn draw_sections(f: &mut Frame, app: &App, area: Rect) {
    let sections = ["Appearance", "Capture", "Analysis", "Automation", "Defense", "Keys"];
    let rows = sections.iter().enumerate().map(|(index, section)| {
        let selected = app.settings_cursor == index;
        let style = if selected {
            Style::default().fg(C_BG()).bg(C_CYAN()).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_FG())
        };
        Row::new([Cell::from(*section).style(style)]).style(if selected { Style::default().bg(C_CYAN()) } else { Style::default().bg(C_BG()) })
    });
    let table = Table::new(rows, [Constraint::Percentage(100)])
        .block(panel("Settings"))
        .style(Style::default().bg(C_BG()));
    f.render_widget(table, area);
}

fn draw_details(f: &mut Frame, app: &App, area: Rect) {
    let lines = match app.settings_cursor {
        0 => vec![
            Line::from(vec![Span::styled("Appearance", heading())]),
            Line::from(format!("Theme: {}", app.selected_theme_name)),
            Line::from("Enter: open theme picker.  \\ also opens it from anywhere."),
            Line::from("Future: compact density, timestamp format, packet color rules."),
        ],
        1 => vec![
            Line::from(vec![Span::styled("Capture", heading())]),
            Line::from(format!("Interface: {}", app.selected_iface)),
            Line::from(format!("Capturing: {}", if app.capturing { "yes" } else { "no" })),
            Line::from(format!("Visible packets: {} / total {}", app.filtered.len(), app.packets.len())),
            Line::from("Enter: toggle capture."),
            Line::from("Future: default interface, capture buffer limits, auto-scroll."),
        ],
        2 => vec![
            Line::from(vec![Span::styled("Analysis Helpers", heading())]),
            Line::from(format!("TLS decrypt helper: {}", path_state(app.tls_tracker.decrypt_helper_path.as_ref()))),
            Line::from(format!("QUIC decode helper: {}", path_state(app.quic_scope.decode_helper_path.as_ref()))),
            Line::from(format!("Capture helper: {}", path_state(app.capture_helper_path.as_ref()))),
            Line::from(format!("Latch helper: {}", path_state(app.latch_helper_path.as_ref()))),
            Line::from(format!("Reputation helper: {}", path_state(app.reputation_helper_path.as_ref()))),
        ],
        3 => vec![
            Line::from(vec![Span::styled("Alert Automation", heading())]),
            Line::from(format!("Mode: {}", app.alert_center.automation_mode)),
            Line::from("Off: findings enter the Alert Center for manual review."),
            Line::from("Watch: high/critical findings are pinned to the investigation tray."),
            Line::from("Triage: Watch behavior plus deterministic priority and next-step advice."),
            Line::from("Enter: cycle mode. No automation mode changes firewall policy."),
        ],
        4 => vec![
            Line::from(vec![Span::styled("Defense", heading())]),
            Line::from(format!("TrafficLatch mode: {}", app.traffic_latch.mode)),
            Line::from(format!("Containment timeout: {}s", app.traffic_latch.expires_seconds)),
            Line::from(format!("Protected addresses: {}", app.traffic_latch.protected_addresses.len())),
            Line::from(format!("Maximum active blocks: {}", app.traffic_latch.max_active_blocks)),
            Line::from(format!("Kill switch: {}", if app.traffic_latch.emergency_stop { "ENGAGED" } else { "ready" })),
            Line::from(format!("Last Guard simulation entries: {}", app.response_preview.len())),
            Line::from("Enter: cycle TrafficLatch mode."),
            Line::from("Auto containment still requires the policy gate."),
            Line::from("!: force monitor mode and stop future automatic blocks."),
        ],
        _ => vec![
            Line::from(vec![Span::styled("Keys", heading())]),
            Line::from("1-5: top-level modes"),
            Line::from("[ / ]: local screen inside Investigate"),
            Line::from("Tab/F2: view drawer"),
            Line::from("m: add packet/alert  M: pin active context to tray"),
            Line::from("Enter: investigate selected packet"),
            Line::from("w: investigation tray / recording outside Investigate"),
            Line::from(",: settings  Esc: close/back"),
        ],
    };
    let hint = Line::from(vec![
        Span::styled(" [j/k] section  [Enter] action  [Esc] close  [,] close ", Style::default().fg(C_FG3())),
    ]);
    let mut content = lines;
    content.push(Line::raw(""));
    content.push(hint);
    f.render_widget(Paragraph::new(content).block(panel("Configuration")).wrap(Wrap { trim: false }), area);
}

fn path_state(path: Option<&std::path::PathBuf>) -> String {
    path.map(|path| path.display().to_string()).unwrap_or_else(|| "not configured".into())
}

fn heading() -> Style {
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
