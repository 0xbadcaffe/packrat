use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table},
};
use crate::app::App;
use crate::net::flow::FlowFlags;
use crate::ui::theme::*;
use crate::ui::helpers::fmt_bytes;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(2)])
        .split(area);

    draw_flow_table(f, app, chunks[0]);
    draw_hints(f, chunks[1]);
}

fn _flag_spans(flags: &FlowFlags) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    if flags.beacon    { spans.push(Span::styled("[BEACON] ",    Style::default().fg(C_YELLOW))); }
    if flags.large     { spans.push(Span::styled("[LARGE] ",     Style::default().fg(C_CYAN))); }
    if flags.encrypted { spans.push(Span::styled("[ENCRYPTED] ", Style::default().fg(C_MAGENTA))); }
    if flags.scan      { spans.push(Span::styled("[SCAN] ",      Style::default().fg(C_RED))); }
    spans
}

fn draw_flow_table(f: &mut Frame, app: &App, area: Rect) {
    let sorted = app.flow_tracker.sorted_flows(&app.flows_sort);

    let header = Row::new(vec![
        Cell::from("Proto").style(Style::default().fg(C_FG2)),
        Cell::from("Endpoint 1").style(Style::default().fg(C_FG2)),
        Cell::from("Endpoint 2").style(Style::default().fg(C_FG2)),
        Cell::from("Pkts").style(Style::default().fg(C_FG2)),
        Cell::from("Bytes").style(Style::default().fg(C_FG2)),
        Cell::from("Duration").style(Style::default().fg(C_FG2)),
        Cell::from("Flags").style(Style::default().fg(C_FG2)),
    ]).style(Style::default().bg(C_BG3)).height(1);

    let visible_h = area.height.saturating_sub(3) as usize;
    let sel = app.flows_selected.unwrap_or(0);
    let offset = if sel >= visible_h { sel - visible_h + 1 } else { 0 };

    let rows: Vec<Row> = sorted.iter().enumerate()
        .skip(offset).take(visible_h)
        .map(|(i, flow)| {
            let selected = app.flows_selected == Some(i);
            let bg = if selected { C_SEL_BG } else { C_BG };
            let fg = if selected { ratatui::style::Color::White } else { C_FG };
            let duration = flow.last_seen - flow.first_seen;
            let dur_str = if duration < 1.0 {
                format!("{:.0}ms", duration * 1000.0)
            } else if duration < 60.0 {
                format!("{:.1}s", duration)
            } else {
                format!("{:.0}m", duration / 60.0)
            };
            let flag_str = {
                let mut s = String::new();
                if flow.flags.beacon    { s.push_str("BEACON "); }
                if flow.flags.large     { s.push_str("LARGE "); }
                if flow.flags.encrypted { s.push_str("ENC "); }
                if flow.flags.scan      { s.push_str("SCAN"); }
                s.trim().to_string()
            };
            let flag_color = if flow.flags.scan { C_RED }
                else if flow.flags.beacon { C_YELLOW }
                else if flow.flags.encrypted { C_MAGENTA }
                else if flow.flags.large { C_CYAN }
                else { C_FG3 };

            Row::new(vec![
                Cell::from(flow.key.proto.clone())
                    .style(Style::default().fg(crate::ui::theme::proto_color(&flow.key.proto)).bg(bg)),
                Cell::from(format!("{}:{}", flow.key.ep1.0, flow.key.ep1.1))
                    .style(Style::default().fg(fg).bg(bg)),
                Cell::from(format!("{}:{}", flow.key.ep2.0, flow.key.ep2.1))
                    .style(Style::default().fg(fg).bg(bg)),
                Cell::from(flow.packets.to_string())
                    .style(Style::default().fg(C_FG2).bg(bg)),
                Cell::from(fmt_bytes(flow.bytes))
                    .style(Style::default().fg(C_FG2).bg(bg)),
                Cell::from(dur_str)
                    .style(Style::default().fg(C_FG3).bg(bg)),
                Cell::from(flag_str)
                    .style(Style::default().fg(flag_color).bg(bg).add_modifier(Modifier::BOLD)),
            ])
        })
        .collect();

    let sort_label = match app.flows_sort {
        crate::net::flow::FlowSort::Bytes   => "bytes",
        crate::net::flow::FlowSort::Packets => "packets",
        crate::net::flow::FlowSort::Time    => "time",
    };

    let widths = [
        Constraint::Length(12),
        Constraint::Length(21),
        Constraint::Length(21),
        Constraint::Length(6),
        Constraint::Length(9),
        Constraint::Length(8),
        Constraint::Min(0),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(
                format!(" Flows [{}] sorted by {} ", sorted.len(), sort_label),
                Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
            )))
        .style(Style::default().bg(C_BG));

    f.render_widget(table, area);
}

fn draw_hints(f: &mut Frame, area: Rect) {
    let hints = Line::from(vec![
        Span::styled("  b", Style::default().fg(C_CYAN)),
        Span::styled(":bytes  ", Style::default().fg(C_FG3)),
        Span::styled("p", Style::default().fg(C_CYAN)),
        Span::styled(":packets  ", Style::default().fg(C_FG3)),
        Span::styled("t", Style::default().fg(C_CYAN)),
        Span::styled(":time  ", Style::default().fg(C_FG3)),
        Span::styled("Enter", Style::default().fg(C_CYAN)),
        Span::styled(":filter packets by IP  ", Style::default().fg(C_FG3)),
        Span::styled("j/k", Style::default().fg(C_CYAN)),
        Span::styled(":navigate  ", Style::default().fg(C_FG3)),
        Span::styled("Flags: ", Style::default().fg(C_FG3)),
        Span::styled("[BEACON]", Style::default().fg(C_YELLOW)),
        Span::styled(" [LARGE]", Style::default().fg(C_CYAN)),
        Span::styled(" [ENC]", Style::default().fg(C_MAGENTA)),
        Span::styled(" [SCAN]", Style::default().fg(C_RED)),
    ]);
    let p = Paragraph::new(hints).style(Style::default().bg(C_BG));
    f.render_widget(p, area);
}
