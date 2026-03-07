use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
};

use crate::ui::theme::*;

pub fn draw(f: &mut Frame) {
    let area = centered_rect(60, 34, f.area());

    // Clear the area behind the popup
    f.render_widget(Clear, area);

    let sections: &[(&str, &[(&str, &str)])] = &[
        ("Navigation", &[
            ("j / ↓",        "Move down"),
            ("k / ↑",        "Move up"),
            ("g",            "Jump to top"),
            ("G",            "Jump to bottom"),
            ("PgDn / PgUp",  "Page down / up"),
            ("Tab",          "Next tab"),
            ("1–6",          "Switch to tab"),
        ]),
        ("Capture", &[
            ("Space",  "Toggle capture on/off"),
            ("C",      "Clear all packets"),
            ("i",      "Switch interface"),
            ("W",      "Toggle PCAP recording"),
        ]),
        ("Filter", &[
            ("/",     "Start filter input"),
            ("Enter", "Apply filter"),
            ("Esc",   "Cancel / clear filter mode"),
        ]),
        ("General", &[
            ("h",   "Show this help"),
            ("Esc", "Close help"),
            ("q",   "Quit"),
        ]),
    ];

    let mut lines: Vec<Line> = vec![Line::raw("")];
    for (title, entries) in sections {
        lines.push(Line::from(vec![
            Span::styled(format!("  {}", title), Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::raw(format!("  {}", "─".repeat(38))));
        for (key, desc) in *entries {
            lines.push(Line::from(vec![
                Span::styled(format!("    {:<16}", key), Style::default().fg(C_CYAN)),
                Span::styled(*desc, Style::default().fg(C_FG2)),
            ]));
        }
        lines.push(Line::raw(""));
    }

    let popup = Paragraph::new(lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(C_CYAN))
            .title(Span::styled(
                " Keyboard Shortcuts — press h or Esc to close ",
                Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
            ))
            .title_alignment(Alignment::Center))
        .style(Style::default().bg(C_BG));

    f.render_widget(popup, area);
}

/// Return a centered Rect with the given percentage width and fixed height (in lines).
fn centered_rect(width_pct: u16, height: u16, r: Rect) -> Rect {
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - width_pct) / 2),
            Constraint::Percentage(width_pct),
            Constraint::Percentage((100 - width_pct) / 2),
        ])
        .split(vert[1])[1]
}
