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

    let objects = &app.carved_objects;

    let header = Row::new(vec![
        Cell::from("ID").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Type").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Size").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Source").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("SHA256").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("YARA Hits").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
    ]).style(Style::default().bg(C_BG2)).height(1);

    let scroll = app.objects_scroll;
    let rows: Vec<Row> = objects.iter().skip(scroll).map(|obj| {
        let yara = if obj.yara_hits.is_empty() {
            "-".into()
        } else {
            obj.yara_hits.join(", ")
        };
        let yara_style = if obj.yara_hits.is_empty() {
            Style::default().fg(C_FG3)
        } else {
            Style::default().fg(C_RED).add_modifier(Modifier::BOLD)
        };
        Row::new(vec![
            Cell::from(format!("#{}", obj.id)).style(Style::default().fg(C_FG3)),
            Cell::from(obj.kind.clone()).style(Style::default().fg(C_CYAN)),
            Cell::from(obj.size_str()).style(Style::default().fg(C_FG2)),
            Cell::from(obj.source.clone()).style(Style::default().fg(C_FG2)),
            Cell::from(obj.sha256[..12.min(obj.sha256.len())].to_string()).style(Style::default().fg(C_FG3)),
            Cell::from(yara).style(yara_style),
        ])
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(6),
        Constraint::Length(20),
        Constraint::Length(9),
        Constraint::Length(36),
        Constraint::Length(14),
        Constraint::Min(20),
    ])
    .header(header)
    .block(Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            format!(" Carved Objects — {} ", objects.len()),
            Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD),
        )))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, chunks[0]);

    let status = Paragraph::new(Line::from(vec![
        Span::styled(
            " [j/k] scroll  [e] export selected  [c] carve streams now",
            Style::default().fg(C_FG3),
        ),
    ])).style(Style::default().bg(C_BG2));
    f.render_widget(status, chunks[1]);
}
