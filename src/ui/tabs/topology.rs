use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph},
};

use crate::app::App;
use crate::ui::helpers::fmt_bytes;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    draw_nodes(f, app, chunks[0]);
    draw_edges(f, app, chunks[1]);
}

fn draw_nodes(f: &mut Frame, app: &App, area: Rect) {
    let top_nodes = app.topology.top_nodes(50);

    let mut items: Vec<ListItem> = Vec::new();
    if top_nodes.is_empty() {
        items.push(ListItem::new(Line::from(vec![
            Span::styled("  No traffic observed yet.", Style::default().fg(C_FG3)),
        ])));
    }
    for (ip, info) in &top_nodes {
        let total_pkts = info.tx_packets + info.rx_packets;
        let total_bytes = info.tx_bytes + info.rx_bytes;
        items.push(ListItem::new(Line::from(vec![
            Span::styled(format!(" {:<18}", ip), Style::default().fg(C_CYAN)),
            Span::styled(format!("{:<7}", total_pkts), Style::default().fg(C_FG2)),
            Span::styled(fmt_bytes(total_bytes), Style::default().fg(C_GREEN)),
        ])));
        items.push(ListItem::new(Line::from(vec![
            Span::styled(format!("   tx:{:<6} rx:{:<6}", info.tx_packets, info.rx_packets),
                Style::default().fg(C_FG3)),
        ])));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            format!(" Nodes [{}] ", app.topology.nodes.len()),
            Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
        ));

    let header = Paragraph::new(Line::from(vec![
        Span::styled(format!(" {:<18} {:<7} {}", "IP Address", "Pkts", "Bytes"),
            Style::default().fg(C_FG2)),
    ])).block(block.clone()).style(Style::default().bg(C_BG));

    // Split area: header row + list
    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    f.render_widget(header, inner[0]);
    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::LEFT | Borders::RIGHT | Borders::BOTTOM)
            .border_style(Style::default().fg(C_BORDER)))
        .style(Style::default().bg(C_BG));
    f.render_widget(list, inner[1]);
}

fn draw_edges(f: &mut Frame, app: &App, area: Rect) {
    let top_edges = app.topology.top_edges(30);

    let mut items: Vec<ListItem> = Vec::new();
    if top_edges.is_empty() {
        items.push(ListItem::new(Line::from(vec![
            Span::styled("  No flows observed yet.", Style::default().fg(C_FG3)),
        ])));
    }
    for (src, dst, info) in &top_edges {
        items.push(ListItem::new(Line::from(vec![
            Span::styled(format!(" {}", src), Style::default().fg(C_CYAN)),
            Span::styled(" → ", Style::default().fg(C_FG3)),
            Span::styled(format!("{}", dst), Style::default().fg(C_GREEN)),
        ])));
        items.push(ListItem::new(Line::from(vec![
            Span::styled(
                format!("   [{:<6}] {:>6} pkts  {}", info.protocol, info.packets, fmt_bytes(info.bytes)),
                Style::default().fg(C_FG3),
            ),
        ])));
    }

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(
                format!(" Flows [{}] ", app.topology.edges.len()),
                Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
            )))
        .style(Style::default().bg(C_BG));
    f.render_widget(list, area);
}
