use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
};

use crate::app::App;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App) {
    let terminal = f.area();
    let width = terminal.width.saturating_sub(2).min(104);
    let height = terminal.height.saturating_sub(2);
    if width < 20 || height < 6 { return; }
    let area = centered_rect(width, height, terminal);

    f.render_widget(Clear, area);

    let sections: &[(&str, &[(&str, &str)])] = &[
        ("Navigation", &[
            ("j / ↓",        "Move down / select next"),
            ("k / ↑",        "Move up / select prev"),
            ("g",            "Jump to top"),
            ("G",            "Jump to bottom"),
            ("PgDn / PgUp",  "Page down / up"),
            ("Tab / F2",     "Open workspace view drawer"),
            ("1–5",          "Traffic / Inspect / Defense / Actions / Case"),
            ("Esc",          "Return from a detail view to workspace home"),
            (",",            "Open settings window"),
            ("H N T O R W G D",  "Direct expert shortcuts remain available"),
        ]),
        ("Capture & Recording", &[
            ("Space",  "Toggle capture on/off"),
            ("C",      "Clear all packets"),
            ("i",      "Switch capture interface"),
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
            ("m",     "Add selected packet or alert to tray"),
            ("M",     "Pin active screen context to tray"),
            ("w",     "Show investigation tray"),
            ("Enter", "Open selected packet in Investigate"),
            ("a",     "Protocol autopsy overlay"),
        ]),
        ("Investigate View", &[
            ("[/]",   "Previous / next packet screen"),
            ("n / p", "Next / previous investigation item"),
            ("j / k", "Scroll current screen"),
            ("d",     "Remove active item from tray"),
            ("l",     "Return to live packet list"),
        ]),
        ("Hosts Tab", &[
            ("s / /",  "Search hosts"),
            ("t",      "Tag selected host"),
            ("T",      "Remove tag from selected host"),
            ("c",      "Clear hosts"),
        ]),
        ("Security Tab", &[
            ("[/]",  "Previous / next detector view"),
            ("a c o w d u t b v i p", "Jump to common detector views"),
            ("l / y", "RouteLedger mode / promote observed routes"),
            ("r", "Refresh selected NetRegistry address with WHOIS"),
            ("C",    "Clear alerts and credentials"),
        ]),
        ("Encrypted View", &[
            ("[/]", "Switch TLS / QUIC scope"),
            ("j / k", "Select TLS session"),
            ("c", "Clear current encrypted-traffic view"),
        ]),
        ("Objects Tab", &[
            ("o y m",   "Objects / YARA Rules / YARA Matches panels"),
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
            Span::styled(format!("  {}", title), Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::raw(format!("  {}", "─".repeat(46))));
        for (key, desc) in *entries {
            lines.push(Line::from(vec![
                Span::styled(format!("    {:<26}", key), Style::default().fg(C_CYAN())),
                Span::styled(*desc, Style::default().fg(C_FG2())),
            ]));
        }
        lines.push(Line::raw(""));
    }

    let visible_lines = area.height.saturating_sub(2) as usize;
    let max_scroll = lines.len().saturating_sub(visible_lines) as u16;
    let popup = Paragraph::new(lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(C_CYAN()).bg(C_BG2()))
            .style(Style::default().bg(C_BG2()))
            .title(Span::styled(
                " Keyboard Reference  [j/k/PgUp/PgDn scroll]  [h/Esc close] ",
                Style::default().fg(C_CYAN()).bg(C_BG2()).add_modifier(Modifier::BOLD),
            ))
            .title_alignment(Alignment::Center))
        .style(Style::default().bg(C_BG2()))
        .scroll((app.help_scroll.min(max_scroll), 0));

    f.render_widget(popup, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    fn rendered_help(width: u16, height: u16, scroll: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = App::new_for_test();
        app.help_scroll = scroll;
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        terminal.backend().buffer().content.iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    #[test]
    fn help_renders_and_scrolls_at_small_terminal_size() {
        let top = rendered_help(80, 24, 0);
        assert!(top.contains("Navigation"));
        let bottom = rendered_help(80, 24, u16::MAX);
        assert!(bottom.contains("General"));
        assert!(bottom.contains("Quit"));
    }

    #[test]
    fn help_renders_at_wide_terminal_size() {
        let output = rendered_help(160, 48, 0);
        assert!(output.contains("Keyboard Reference"));
        assert!(output.contains("Capture & Recording"));
    }
}

/// Return a centered Rect with the given percentage width and fixed height (in lines).
fn centered_rect(width: u16, height: u16, r: Rect) -> Rect {
    Rect::new(
        r.x + r.width.saturating_sub(width) / 2,
        r.y + r.height.saturating_sub(height) / 2,
        width,
        height,
    )
}
