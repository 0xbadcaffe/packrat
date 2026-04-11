use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
};

use crate::ui::theme::*;

pub fn draw(f: &mut Frame) {
    let area = centered_rect(70, 42, f.area());

    f.render_widget(Clear, area);

    let sections: &[(&str, &[(&str, &str)])] = &[
        ("Navigation", &[
            ("j / ↓",        "Move down / select next"),
            ("k / ↑",        "Move up / select prev"),
            ("g",            "Jump to top"),
            ("G",            "Jump to bottom"),
            ("PgDn / PgUp",  "Page down / up"),
            ("Tab",          "Next tab"),
            ("1–0",          "Switch to tabs 1–10"),
            ("H N T O R W G D",  "Hosts / Notebook / TLS / Objects / Rules / Workbench / Graph / Diff"),
        ]),
        ("Capture & Recording", &[
            ("Space",  "Toggle capture on/off"),
            ("C",      "Clear all packets"),
            ("i",      "Switch capture interface"),
            ("w",      "Toggle PCAP recording"),
            ("B",      "Snapshot baseline for diff"),
        ]),
        ("Analysis & Export", &[
            ("?",   "Open global command palette"),
            ("X",   "Export case bundle (JSON)"),
            ("I",   "Reload IOC feeds from disk"),
            ("a",   "Protocol autopsy (Packets tab)"),
            ("f",   "Open TCP stream (Flows tab)"),
        ]),
        ("Packets Tab", &[
            ("/",     "Start display filter"),
            ("Enter", "Load packet in Workbench"),
            ("a",     "Protocol autopsy overlay"),
        ]),
        ("Hosts Tab", &[
            ("s / /",  "Search hosts"),
            ("t",      "Tag selected host"),
            ("T",      "Remove tag from selected host"),
            ("c",      "Clear hosts"),
        ]),
        ("Security Tab", &[
            ("[/]",  "Previous / next sub-tab"),
            ("a c o w d u t b v i p", "Jump to sub-tab directly"),
            ("C",    "Clear alerts and credentials"),
        ]),
        ("Objects Tab", &[
            ("o y m",   "Objects / YARA Rules / YARA Matches sub-tab"),
            ("r",       "Reload YARA rules from disk"),
            ("s",       "Force YARA rescan of all objects"),
        ]),
        ("Rules Tab", &[
            ("t",      "Toggle selected rule on/off"),
            ("r",      "Reload rules from disk"),
            ("C",      "Clear rule hits"),
        ]),
        ("Diff Tab", &[
            ("B",   "Set baseline (global, any tab)"),
            ("d",   "Compute diff vs current packets"),
            ("X",   "Clear diff results"),
        ]),
        ("General", &[
            ("h",   "Show this help"),
            ("Esc", "Close help / cancel"),
            ("q / Ctrl-C", "Quit"),
        ]),
    ];

    let mut lines: Vec<Line> = vec![Line::raw("")];
    for (title, entries) in sections {
        lines.push(Line::from(vec![
            Span::styled(format!("  {}", title), Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::raw(format!("  {}", "─".repeat(46))));
        for (key, desc) in *entries {
            lines.push(Line::from(vec![
                Span::styled(format!("    {:<26}", key), Style::default().fg(C_CYAN)),
                Span::styled(*desc, Style::default().fg(C_FG2)),
            ]));
        }
        lines.push(Line::raw(""));
    }

    let popup = Paragraph::new(lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(C_CYAN).bg(C_BG2))
            .style(Style::default().bg(C_BG2))
            .title(Span::styled(
                " Keyboard Shortcuts — h / Esc to close ",
                Style::default().fg(C_CYAN).bg(C_BG2).add_modifier(Modifier::BOLD),
            ))
            .title_alignment(Alignment::Center))
        .style(Style::default().bg(C_BG2));

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
