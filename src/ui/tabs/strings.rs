use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::Span,
    widgets::{Block, BorderType, Borders, Cell, Row, Table},
};

use crate::app::App;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let all = crate::sim::strings::all_strings();
    let filt: Vec<_> = if app.strings_filter.is_empty() {
        all.iter().collect()
    } else {
        let f = app.strings_filter.to_lowercase();
        all.iter()
            .filter(|s| s.value.to_lowercase().contains(&f) || s.kind.label().contains(&f))
            .collect()
    };

    let header = Row::new(vec![
        Cell::from("Offset").style(Style::default().fg(C_FG2)),
        Cell::from("Len").style(Style::default().fg(C_FG2)),
        Cell::from("String").style(Style::default().fg(C_FG2)),
        Cell::from("Type").style(Style::default().fg(C_FG2)),
    ]).style(Style::default().bg(C_BG3)).height(1);

    let rows: Vec<Row> = filt.iter().map(|s| {
        let (val_color, type_color) =
            if s.kind.is_sensitive() { (C_RED, C_RED) } else { (C_GREEN, C_FG3) };
        Row::new(vec![
            Cell::from(s.offset.clone()).style(Style::default().fg(C_FG3)),
            Cell::from(s.length.to_string()).style(Style::default().fg(C_YELLOW)),
            Cell::from(s.value.clone()).style(Style::default().fg(val_color)),
            Cell::from(s.kind.label()).style(Style::default().fg(type_color)),
        ])
    }).collect();

    use ratatui::layout::Constraint;
    let widths = [
        Constraint::Length(12),
        Constraint::Length(6),
        Constraint::Min(0),
        Constraint::Length(14),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(
                format!(" Strings [{} shown] ", filt.len()),
                Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
            )))
        .style(Style::default().bg(C_BG));

    f.render_widget(table, area);
}
