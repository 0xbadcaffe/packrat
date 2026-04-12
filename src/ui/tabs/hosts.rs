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

    // Search bar / tag input bar
    draw_top_bar(f, app, chunks[0]);

    // Host table
    let hosts: Vec<_> = if app.hosts_search.is_empty() {
        app.hosts.all()
    } else {
        app.hosts.search(&app.hosts_search)
    };

    draw_host_table(f, app, &hosts, chunks[1]);

    // Status bar
    draw_status_bar(f, app, chunks[2]);
}

fn draw_top_bar(f: &mut Frame, app: &App, area: Rect) {
    if app.hosts_tagging {
        let bar = Paragraph::new(Line::from(vec![
            Span::styled(" Tag: ", Style::default().fg(C_GREEN()).add_modifier(Modifier::BOLD)),
            Span::styled(
                format!("{}_", app.hosts_tag_input),
                Style::default().fg(C_CYAN()),
            ),
            Span::styled("  [Enter] apply  [Esc] cancel", Style::default().fg(C_FG3())),
        ])).block(Block::default().borders(Borders::ALL)
            .border_style(Style::default().fg(C_GREEN()))
            .title(Span::styled(" Add Tag ", Style::default().fg(C_GREEN()).add_modifier(Modifier::BOLD))));
        f.render_widget(bar, area);
        return;
    }

    let search_display = if app.hosts_searching {
        format!("{}_", app.hosts_search)
    } else if app.hosts_search.is_empty() {
        "<press s to search hosts>".into()
    } else {
        app.hosts_search.clone()
    };
    let search_color = if app.hosts_searching { C_CYAN() }
        else if app.hosts_search.is_empty() { C_FG3() }
        else { C_YELLOW() };

    let search_bar = Paragraph::new(Line::from(vec![
        Span::styled(" Search: ", Style::default().fg(C_FG2())),
        Span::styled(search_display, Style::default().fg(search_color)),
    ])).block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(C_BORDER()))
        .title(Span::styled(" Hosts ", Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD))));
    f.render_widget(search_bar, area);
}

fn draw_host_table(f: &mut Frame, app: &App, hosts: &[&crate::model::hosts::Host], area: Rect) {
    let header = Row::new(vec![
        Cell::from("IP / Hostname").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("Geo").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("MAC").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("Protocols").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("Ports").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("Bytes↑").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("Bytes↓").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("Pkts↑").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("Alerts").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("OS Guess").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("Tags").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
    ]).style(Style::default().bg(C_BG2())).height(1);

    let scroll = app.hosts_scroll;
    let visible_height = area.height.saturating_sub(3) as usize;

    // Compute scroll offset so cursor stays in view
    let scroll_offset = if scroll < visible_height { 0 } else { scroll - visible_height + 1 };

    let rows: Vec<Row> = hosts.iter().enumerate().skip(scroll_offset).map(|(idx, h)| {
        let selected = idx == scroll;
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
            Style::default().fg(C_RED()).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_FG2())
        };
        let geo = h.geo.as_deref().unwrap_or("??");
        let geo_color = match geo {
            "LAN" | "LOOP" | "LINK" => C_FG3(),
            "US"   => C_CYAN(),
            "EU"   => C_GREEN(),
            "CN"   => C_RED(),
            "AWS" | "GCP" | "AZURE" | "CDN" => C_ORANGE(),
            "??"   => C_FG3(),
            _      => C_YELLOW(),
        };
        let mut tags: Vec<&str> = h.tags.iter().map(|s| s.as_str()).collect();
        tags.sort();
        let tags_str = tags.join(",");
        let tags_style = if tags.is_empty() {
            Style::default().fg(C_FG3())
        } else {
            Style::default().fg(C_ORANGE()).add_modifier(Modifier::BOLD)
        };

        let row_style = if selected {
            Style::default().bg(C_BG2()).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };

        Row::new(vec![
            Cell::from(name).style(Style::default().fg(C_CYAN())),
            Cell::from(geo.to_string()).style(Style::default().fg(geo_color).add_modifier(Modifier::BOLD)),
            Cell::from(mac).style(Style::default().fg(C_FG2())),
            Cell::from(protos).style(Style::default().fg(C_GREEN())),
            Cell::from(ports_str).style(Style::default().fg(C_FG2())),
            Cell::from(crate::ui::fmt_bytes(h.bytes_out)).style(Style::default().fg(C_FG2())),
            Cell::from(crate::ui::fmt_bytes(h.bytes_in)).style(Style::default().fg(C_FG2())),
            Cell::from(h.pkts_out.to_string()).style(Style::default().fg(C_FG2())),
            Cell::from(h.alert_count.to_string()).style(alert_style),
            Cell::from(h.os_guess.as_deref().unwrap_or("-").to_string()).style(Style::default().fg(C_FG3())),
            Cell::from(if tags_str.is_empty() { "-".into() } else { tags_str }).style(tags_style),
        ]).style(row_style)
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(28),
        Constraint::Length(7),
        Constraint::Length(18),
        Constraint::Length(20),
        Constraint::Length(22),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Length(12),
        Constraint::Min(10),
    ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(C_BORDER())))
    .style(Style::default().bg(C_BG()));
    f.render_widget(table, area);
}

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let status = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" {} hosts  [s] search  [j/k] scroll  [t] tag  [T] untag  [c] clear host",
                app.hosts.len()),
            Style::default().fg(C_FG3()),
        ),
    ])).style(Style::default().bg(C_BG2()));
    f.render_widget(status, area);
}
