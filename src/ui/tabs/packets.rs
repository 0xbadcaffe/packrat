use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, List, ListItem, Paragraph, Row, Table, Wrap},
};

use crate::app::App;
use crate::ui::helpers::{truncate, pad_right};
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(38), Constraint::Min(0)])
        .split(area);

    draw_packet_list(f, app, chunks[0]);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Min(0)])
        .split(chunks[1]);

    draw_protocol_tree(f, app, bottom[0]);
    draw_hex_dump(f, app, bottom[1]);
}

fn draw_packet_list(f: &mut Frame, app: &App, area: Rect) {
    if app.packets.is_empty() {
        let msg = if !app.capturing && app.selected_iface != "simulated" {
            vec![
                Line::raw(""),
                Line::from(vec![Span::styled(
                    format!("  Real capture on '{}' is not available.", app.selected_iface),
                    Style::default().fg(C_RED).add_modifier(Modifier::BOLD),
                )]),
                Line::raw(""),
                Line::from(vec![Span::styled(
                    "  Rebuild with: cargo build --release --features real-capture",
                    Style::default().fg(C_YELLOW),
                )]),
                Line::raw(""),
                Line::from(vec![
                    Span::styled("  Press ", Style::default().fg(C_FG2)),
                    Span::styled("i", Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD)),
                    Span::styled(" to choose a different interface.", Style::default().fg(C_FG2)),
                ]),
            ]
        } else {
            vec![
                Line::raw(""),
                Line::from(vec![Span::styled("  waiting for packets…", Style::default().fg(C_FG3))]),
            ]
        };
        f.render_widget(Paragraph::new(msg).style(Style::default().bg(C_BG)), area);
        return;
    }

    let header = Row::new(vec![
        Cell::from("No.").style(Style::default().fg(C_FG2)),
        Cell::from("Time").style(Style::default().fg(C_FG2)),
        Cell::from("Source").style(Style::default().fg(C_FG2)),
        Cell::from("Destination").style(Style::default().fg(C_FG2)),
        Cell::from("Protocol").style(Style::default().fg(C_FG2)),
        Cell::from("VLAN").style(Style::default().fg(C_FG2)),
        Cell::from("Len").style(Style::default().fg(C_FG2)),
        Cell::from("Info").style(Style::default().fg(C_FG2)),
    ]).style(Style::default().bg(C_BG3)).height(1);

    let visible_h = area.height.saturating_sub(3) as usize;
    let sel = app.selected.unwrap_or(0);
    let offset = if sel >= visible_h { sel - visible_h + 1 } else { 0 };

    let rows: Vec<Row> = app.filtered.iter().enumerate()
        .skip(offset).take(visible_h)
        .filter_map(|(fi, &pi)| app.packets.get(pi).map(|p| (fi, p)))
        .map(|(fi, p)| {
            let selected = app.selected == Some(fi);
            let bg = if selected { C_SEL_BG } else { C_BG };
            let fg = if selected { Color::White } else { C_FG };
            let proto_fg = if selected { Color::White } else { proto_color(&p.protocol) };
            let vlan_str = p.vlan_id.map(|v| v.to_string()).unwrap_or_default();

            Row::new(vec![
                Cell::from(p.no.to_string()).style(Style::default().fg(C_FG3).bg(bg)),
                Cell::from(format!("{:.4}", p.timestamp)).style(Style::default().fg(C_FG2).bg(bg)),
                Cell::from(p.src.clone()).style(Style::default().fg(fg).bg(bg)),
                Cell::from(p.dst.clone()).style(Style::default().fg(fg).bg(bg)),
                Cell::from(p.protocol.clone()).style(Style::default().fg(proto_fg).bg(bg).add_modifier(Modifier::BOLD)),
                Cell::from(vlan_str).style(Style::default().fg(C_FG3).bg(bg)),
                Cell::from(p.length.to_string()).style(Style::default().fg(C_FG2).bg(bg)),
                Cell::from(truncate(&p.info, 55)).style(Style::default().fg(C_FG2).bg(bg)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(6),
        Constraint::Length(9),
        Constraint::Length(15),
        Constraint::Length(15),
        Constraint::Length(9),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Min(0),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(
                format!(" Packets [{}/{}] ", app.filtered.len(), app.packets.len()),
                Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
            )))
        .style(Style::default().bg(C_BG));

    f.render_widget(table, area);
}

fn draw_protocol_tree(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(" Protocol Tree ", Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD)))
        .style(Style::default().bg(C_BG));

    let Some(pkt) = app.selected_packet() else {
        let p = Paragraph::new("No packet selected.\n\nPress Space to start capture,\nthen j/k to navigate.")
            .style(Style::default().fg(C_FG3))
            .block(block);
        f.render_widget(p, area);
        return;
    };

    let sections = app.dissect_packet(pkt);
    let mut items: Vec<ListItem> = Vec::new();

    for sec in &sections {
        items.push(ListItem::new(Line::from(vec![
            Span::styled("▼ ", Style::default().fg(C_YELLOW)),
            Span::styled(
                truncate(&sec.title, (area.width as usize).saturating_sub(6)),
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
        ])));

        if sec.expanded {
            for field in &sec.fields {
                let key = pad_right(&field.key, 20);
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(key, Style::default().fg(C_FG2)),
                    Span::styled(" ", Style::default()),
                    Span::styled(field.val.clone(), Style::default().fg(crate::ui::theme::field_color(&field.color))),
                ])));
            }
        }
    }

    let list = List::new(items).block(block).style(Style::default().bg(C_BG));
    f.render_widget(list, area);
}

fn draw_hex_dump(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(" Hex Dump ", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)))
        .style(Style::default().bg(C_BG));

    let Some(pkt) = app.selected_packet() else {
        let p = Paragraph::new("No packet selected.")
            .style(Style::default().fg(C_FG3))
            .block(block)
            .wrap(Wrap { trim: false });
        f.render_widget(p, area);
        return;
    };

    let bytes = &pkt.bytes;
    let bytes_per_row = 16usize;
    let mut lines: Vec<Line> = Vec::new();

    for (row_i, chunk) in bytes.chunks(bytes_per_row).enumerate() {
        let offset = row_i * bytes_per_row;
        let mut spans: Vec<Span> = Vec::new();

        spans.push(Span::styled(format!("{:04x}  ", offset), Style::default().fg(C_FG3)));

        for (i, &b) in chunk.iter().enumerate() {
            let color = if b == 0 { C_FG3 } else if b >= 32 && b < 127 { C_GREEN } else { C_CYAN };
            spans.push(Span::styled(format!("{:02x}", b), Style::default().fg(color)));
            spans.push(Span::raw(" "));
            if i == 7 { spans.push(Span::raw(" ")); }
        }
        for i in chunk.len()..bytes_per_row {
            spans.push(Span::raw("   "));
            if i == 7 { spans.push(Span::raw(" ")); }
        }
        spans.push(Span::raw(" │ "));

        for &b in chunk.iter() {
            let (ch, color) = if b >= 32 && b < 127 { (b as char, C_GREEN) } else { ('.', C_FG3) };
            spans.push(Span::styled(ch.to_string(), Style::default().fg(color)));
        }
        lines.push(Line::from(spans));
    }

    let mut all_lines = vec![
        Line::from(vec![Span::styled(
            format!(" {} bytes │ {} rows ", pkt.length, lines.len()),
            Style::default().fg(C_FG3),
        )]),
        Line::raw(""),
    ];
    all_lines.extend(lines);

    let p = Paragraph::new(all_lines).block(block).style(Style::default().bg(C_BG));
    f.render_widget(p, area);
}
