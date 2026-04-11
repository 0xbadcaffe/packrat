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
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(1)])
        .split(area);

    // Search bar
    let search_display = if app.hosts_searching {
        format!("{}_", app.hosts_search)
    } else if app.hosts_search.is_empty() {
        "<press s to search hosts>".into()
    } else {
        app.hosts_search.clone()
    };
    let search_color = if app.hosts_searching { C_CYAN }
        else if app.hosts_search.is_empty() { C_FG3 }
        else { C_YELLOW };

    let search_bar = Paragraph::new(Line::from(vec![
        Span::styled(" Search: ", Style::default().fg(C_FG2)),
        Span::styled(search_display, Style::default().fg(search_color)),
    ])).block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(" Hosts ", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD))));
    f.render_widget(search_bar, chunks[0]);

    // Host table
    let hosts: Vec<_> = if app.hosts_search.is_empty() {
        app.hosts.all()
    } else {
        app.hosts.search(&app.hosts_search)
    };

    let header = Row::new(vec![
        Cell::from("IP / Hostname").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("MAC").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Protocols").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Ports").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Bytes↑").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Bytes↓").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Pkts↑").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Alerts").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("OS Guess").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
    ]).style(Style::default().bg(C_BG2)).height(1);

    let scroll = app.hosts_scroll;
    let visible = hosts.iter().skip(scroll).take(chunks[1].height.saturating_sub(3) as usize);

    let rows: Vec<Row> = visible.enumerate().map(|(_idx, h)| {
        let name = if let Some(hn) = h.hostnames.iter().next() {
            format!("{} ({})", h.ip, hn)
        } else {
            h.ip.clone()
        };
        let mac = h.mac.as_deref().unwrap_or("-").to_string();
        let mut protos: Vec<&str> = h.protocols.iter().map(|s| s.as_str()).collect();
        protos.sort();
        let protos = protos.join(",");
        let mut ports: Vec<u16> = h.open_ports.iter().copied().collect();
        ports.sort();
        let ports_str = if ports.len() > 6 {
            format!("{} +{}", ports.iter().take(6).map(|p| p.to_string()).collect::<Vec<_>>().join(","), ports.len() - 6)
        } else {
            ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")
        };
        let alert_style = if h.alert_count > 0 {
            Style::default().fg(C_RED).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_FG2)
        };
        Row::new(vec![
            Cell::from(name).style(Style::default().fg(C_CYAN)),
            Cell::from(mac).style(Style::default().fg(C_FG2)),
            Cell::from(protos).style(Style::default().fg(C_GREEN)),
            Cell::from(ports_str).style(Style::default().fg(C_FG2)),
            Cell::from(crate::ui::fmt_bytes(h.bytes_out)).style(Style::default().fg(C_FG2)),
            Cell::from(crate::ui::fmt_bytes(h.bytes_in)).style(Style::default().fg(C_FG2)),
            Cell::from(h.pkts_out.to_string()).style(Style::default().fg(C_FG2)),
            Cell::from(h.alert_count.to_string()).style(alert_style),
            Cell::from(h.os_guess.as_deref().unwrap_or("-").to_string()).style(Style::default().fg(C_FG3)),
        ])
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(28),
        Constraint::Length(18),
        Constraint::Length(20),
        Constraint::Length(22),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Min(10),
    ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(C_BORDER)))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, chunks[1]);

    // Status bar
    let status = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" {} hosts  [s] search  [j/k] scroll  [c] clear", app.hosts.len()),
            Style::default().fg(C_FG3),
        ),
    ])).style(Style::default().bg(C_BG2));
    f.render_widget(status, chunks[2]);
}
