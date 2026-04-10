use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
};

use crate::app::App;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    draw_form(f, app, chunks[0]);
    draw_preview(f, app, chunks[1]);
}

fn draw_form(f: &mut Frame, app: &App, area: Rect) {
    let inner_h = area.height.saturating_sub(4) as usize;
    let field_rows: Vec<Row> = app.craft.fields.iter().enumerate().map(|(i, field)| {
        let is_focused = i == app.craft.focused;
        let is_editing = is_focused && app.craft.editing;

        let label_style = if is_focused {
            Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_FG2)
        };

        let value_str = if is_editing {
            format!("{}_", field.value)
        } else {
            field.value.clone()
        };
        let value_style = if is_editing {
            Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)
        } else if is_focused {
            Style::default().fg(C_GREEN)
        } else {
            Style::default().fg(C_FG)
        };

        let hint_style = Style::default().fg(C_FG3);
        let hint = if is_focused { field.hint } else { "" };

        Row::new(vec![
            Cell::from(Span::styled(field.label, label_style)),
            Cell::from(Span::styled(value_str, value_style)),
            Cell::from(Span::styled(hint, hint_style)),
        ])
        .height(1)
    }).collect();

    let table = Table::new(
        field_rows,
        [
            Constraint::Length(14),
            Constraint::Percentage(45),
            Constraint::Min(0),
        ],
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(" Packet Crafter ", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD))),
    )
    .style(Style::default().bg(C_BG));

    f.render_widget(table, area);

    // Result / status line at the bottom of the form area
    let status_area = Rect {
        x: area.x + 1,
        y: area.y + area.height.saturating_sub(2),
        width: area.width.saturating_sub(2),
        height: 1,
    };

    let (status_text, status_color) = match &app.craft.result {
        Some(Ok(msg))  => (msg.as_str(), C_GREEN),
        Some(Err(msg)) => (msg.as_str(), C_RED),
        None           => ("[Tab] next field  [Enter/e] edit  [Space/x] inject packet  [q] quit", C_FG3),
    };
    f.render_widget(
        Paragraph::new(Span::styled(status_text, Style::default().fg(status_color))),
        status_area,
    );
}

fn draw_preview(f: &mut Frame, app: &App, area: Rect) {
    // Split: top = hex dump, bottom = decoded fields
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    // Build a preview packet (without injecting it)
    let pkt_result = app.craft.build_packet(0);

    // ─── Hex dump ─────────────────────────────────────────────────────────────
    let hex_lines: Vec<Line> = match &pkt_result {
        Ok(pkt) => {
            pkt.bytes.chunks(16).enumerate().map(|(row, chunk)| {
                let offset = Span::styled(
                    format!("{:04x}  ", row * 16),
                    Style::default().fg(C_FG3),
                );
                let hex_part: String = chunk.iter()
                    .map(|b| format!("{:02x} ", b))
                    .collect::<Vec<_>>()
                    .join("");
                let padding = " ".repeat((16 - chunk.len()) * 3);
                let ascii: String = chunk.iter()
                    .map(|&b| if b >= 32 && b < 127 { b as char } else { '.' })
                    .collect();
                Line::from(vec![
                    offset,
                    Span::styled(format!("{}{}", hex_part, padding), Style::default().fg(C_CYAN)),
                    Span::styled(format!(" │{}", ascii), Style::default().fg(C_FG2)),
                ])
            }).collect()
        }
        Err(e) => vec![
            Line::from(Span::styled(format!("  Error: {}", e), Style::default().fg(C_RED))),
        ],
    };

    f.render_widget(
        Paragraph::new(hex_lines)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(" Hex Preview ", Style::default().fg(C_FG2))))
            .style(Style::default().bg(C_BG)),
        chunks[0],
    );

    // ─── Field summary ────────────────────────────────────────────────────────
    let summary_lines: Vec<Line> = match &pkt_result {
        Ok(pkt) => vec![
            Line::from(vec![
                Span::styled("  Protocol: ", Style::default().fg(C_FG2)),
                Span::styled(&pkt.protocol, Style::default().fg(C_CYAN)),
            ]),
            Line::from(vec![
                Span::styled("  Src:       ", Style::default().fg(C_FG2)),
                Span::styled(format!("{}{}", pkt.src,
                    pkt.src_port.map(|p| format!(":{}", p)).unwrap_or_default()),
                    Style::default().fg(C_GREEN)),
            ]),
            Line::from(vec![
                Span::styled("  Dst:       ", Style::default().fg(C_FG2)),
                Span::styled(format!("{}{}", pkt.dst,
                    pkt.dst_port.map(|p| format!(":{}", p)).unwrap_or_default()),
                    Style::default().fg(C_ORANGE)),
            ]),
            Line::from(vec![
                Span::styled("  Length:    ", Style::default().fg(C_FG2)),
                Span::styled(format!("{} bytes", pkt.length), Style::default().fg(C_YELLOW)),
            ]),
            Line::from(vec![
                Span::styled("  Info:      ", Style::default().fg(C_FG2)),
                Span::styled(&pkt.info, Style::default().fg(C_FG)),
            ]),
        ],
        Err(e) => vec![
            Line::from(Span::styled(format!("  {}", e), Style::default().fg(C_RED))),
        ],
    };

    f.render_widget(
        Paragraph::new(summary_lines)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(" Packet Summary ", Style::default().fg(C_FG2))))
            .wrap(Wrap { trim: false })
            .style(Style::default().bg(C_BG)),
        chunks[1],
    );
}
