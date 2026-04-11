use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};
use crate::app::App;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(area);

    let sessions = app.tls_tracker.all();

    let header = Row::new(vec![
        Cell::from("Flow").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("SNI").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Version").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Cipher").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("JA3").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Flags").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
    ]).style(Style::default().bg(C_BG2)).height(1);

    let scroll = app.tls_scroll;
    let rows: Vec<Row> = sessions.iter().skip(scroll).map(|s| {
        let sni = s.sni.as_deref().unwrap_or("-").to_string();
        let ver = s.version_str().to_string();
        let cipher = s.cipher_suite
            .map(|cs| format!("{} (0x{cs:04x})", crate::analysis::tls::cipher_name(cs)))
            .unwrap_or_else(|| "-".into());
        let ja3 = s.ja3.as_deref().map(|j| &j[..j.len().min(12)]).unwrap_or("-").to_string();
        let flags = if s.is_weak() { "WEAK" } else { "ok" }.to_string();
        let flag_style = if s.is_weak() {
            Style::default().fg(C_RED).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_GREEN)
        };
        Row::new(vec![
            Cell::from(s.flow_id.clone()).style(Style::default().fg(C_FG3)),
            Cell::from(sni).style(Style::default().fg(C_CYAN)),
            Cell::from(ver).style(Style::default().fg(C_FG2)),
            Cell::from(cipher).style(Style::default().fg(C_FG2)),
            Cell::from(ja3).style(Style::default().fg(C_FG3)),
            Cell::from(flags).style(flag_style),
        ])
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(30),
        Constraint::Length(28),
        Constraint::Length(12),
        Constraint::Length(34),
        Constraint::Length(14),
        Constraint::Length(6),
    ])
    .header(header)
    .block(Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            format!(" TLS Intelligence — {} sessions ", sessions.len()),
            Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD),
        )))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, chunks[0]);

    let status = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" {} sessions  {} with SNI  {} weak  [j/k] scroll",
                sessions.len(),
                app.tls_tracker.with_sni().len(),
                app.tls_tracker.weak_sessions().len(),
            ),
            Style::default().fg(C_FG3),
        ),
    ])).style(Style::default().bg(C_BG2));
    f.render_widget(status, chunks[1]);
}
