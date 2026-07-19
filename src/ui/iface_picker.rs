use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

use crate::app::App;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let show_full_banner =
        area.height >= 17 && area.width >= crate::ui::ascii::FULL_STARTUP_MIN_WIDTH;
    let banner_height = if show_full_banner { 9 } else { 3 };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(banner_height), // banner
            Constraint::Length(2),  // header
            Constraint::Min(0),     // list
            Constraint::Length(1),  // hint
        ])
        .split(area);

    draw_banner(f, chunks[0]);
    draw_header(f, chunks[1]);
    draw_list(f, app, chunks[2]);
    draw_hint(f, chunks[3]);
}

fn draw_banner(f: &mut Frame, area: Rect) {
    const MATRIX_BRIGHT: Color = Color::Rgb(0, 255, 136);
    const MATRIX_GREEN: Color = Color::Rgb(0, 221, 0);
    const MATRIX_DIM: Color = Color::Rgb(0, 119, 34);

    if area.height < 8 || area.width < crate::ui::ascii::FULL_STARTUP_MIN_WIDTH {
        let mark = if area.width >= crate::ui::ascii::COMPACT_STARTUP_MARK.len() as u16 {
            crate::ui::ascii::COMPACT_STARTUP_MARK
        } else {
            crate::ui::ascii::NARROW_STARTUP_MARK
        };
        let banner = Paragraph::new(vec![
            Line::raw(""),
            Line::from(Span::styled(
                mark,
                Style::default().fg(MATRIX_BRIGHT).add_modifier(Modifier::BOLD),
            )),
        ]).style(Style::default().bg(Color::Black));
        f.render_widget(banner, area);
        return;
    }
    let mut banner = vec![Line::raw("")];
    let show_icon = area.width >= crate::ui::ascii::ICON_STARTUP_MIN_WIDTH;
    for index in 0..crate::ui::ascii::PACKRAT_ICON.len() {
        let mut spans = Vec::new();
        if show_icon {
            spans.push(Span::styled(
                format!("{:<28}", crate::ui::ascii::PACKRAT_ICON[index]),
                Style::default().fg(MATRIX_DIM),
            ));
            spans.push(Span::raw("  "));
        }
        if let Some(line) = crate::ui::ascii::STARTUP_MARK.get(index) {
            let color = if index < 5 { MATRIX_BRIGHT } else { MATRIX_GREEN };
            spans.push(Span::styled(
                *line,
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ));
        }
        banner.push(Line::from(spans));
    }
    banner.push(Line::from(Span::styled(
        format!(" PACKRAT // network evidence console  v{}", env!("CARGO_PKG_VERSION")),
        Style::default().fg(MATRIX_DIM),
    )));
    f.render_widget(Paragraph::new(banner).style(Style::default().bg(Color::Black)), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    fn render(width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = App::new_for_test();
        app.iface_list = vec!["eth0".into(), "simulated".into()];
        terminal.draw(|frame| {
            let area = frame.area();
            draw(frame, &app, area);
        }).unwrap();
        terminal.backend().buffer().content.iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    #[test]
    fn selector_keeps_banner_interface_and_controls_visible() {
        let normal = render(100, 24);
        assert!(normal.contains(".--~~,__"));
        assert!(normal.contains("____  ___   ________"));
        assert!(normal.contains("network evidence console"));
        assert!(normal.contains("eth0"));
        assert!(normal.contains("start capture"));

        let compact = render(60, 14);
        assert!(compact.contains("PACKRAT //"));
        assert!(compact.contains("eth0"));
        assert!(compact.contains("start capture"));

        let medium = render(80, 24);
        assert!(medium.contains("____  ___   ________"));
        assert!(!medium.contains(".--~~,__"));
        assert!(medium.contains("eth0"));

        let tall_and_narrow = render(28, 24);
        assert!(tall_and_narrow.contains("PACKRAT"));
        assert!(!tall_and_narrow.contains("PACKRAT //"));
        assert!(tall_and_narrow.contains("eth0"));
    }
}

fn draw_header(f: &mut Frame, area: Rect) {
    let header = Paragraph::new(Line::from(vec![
        Span::styled("  Select network interface", Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD)),
        Span::styled("  ─────────────────────────────────", Style::default().fg(C_BORDER())),
    ])).style(Style::default().bg(C_BG()));
    f.render_widget(header, area);
}

fn draw_list(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app.iface_list.iter().enumerate().map(|(i, name)| {
        let is_sel = i == app.iface_sel;
        let label = if name == "simulated" {
            format!("  {}  (built-in, no root required)", name)
        } else {
            format!("  {}", name)
        };
        if is_sel {
            ListItem::new(label)
                .style(Style::default().fg(Color::Black).bg(C_CYAN()).add_modifier(Modifier::BOLD))
        } else {
            ListItem::new(label).style(Style::default().fg(C_FG2()).bg(C_BG()))
        }
    }).collect();

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::LEFT)
            .border_style(Style::default().fg(C_BORDER())))
        .style(Style::default().bg(C_BG()));
    f.render_widget(list, area);
}

fn draw_hint(f: &mut Frame, area: Rect) {
    let hint = Line::from(vec![
        Span::styled("  j/k", Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Span::styled(" navigate   ", Style::default().fg(C_FG3())),
        Span::styled("Space/Enter", Style::default().fg(C_GREEN()).add_modifier(Modifier::BOLD)),
        Span::styled(" start capture   ", Style::default().fg(C_FG3())),
        Span::styled("q", Style::default().fg(C_RED()).add_modifier(Modifier::BOLD)),
        Span::styled(" quit", Style::default().fg(C_FG3())),
    ]);
    f.render_widget(Paragraph::new(hint).style(Style::default().bg(C_BG2())), area);
}
