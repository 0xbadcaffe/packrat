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
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // banner
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
    let mut banner = vec![Line::raw("")];
    banner.extend(crate::ui::ascii::STARTUP_MARK.iter().map(|line| {
        Line::from(Span::styled(*line, Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD)))
    }));
    banner.push(Line::raw(""));
    banner.push(Line::from(Span::styled(
        " network investigation / deterministic detection / controlled response  v0.4.0",
        Style::default().fg(C_FG3()),
    )));
    f.render_widget(Paragraph::new(banner).style(Style::default().bg(C_BG())), area);
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
