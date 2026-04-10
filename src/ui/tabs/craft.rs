use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
};

use crate::app::App;
use crate::craft::{parse_tcp_flags, parse_icmp_type_code};
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

        let hint = if is_focused { field.hint } else { "" };

        Row::new(vec![
            Cell::from(Span::styled(field.label, label_style)),
            Cell::from(Span::styled(value_str, value_style)),
            Cell::from(Span::styled(hint, Style::default().fg(C_FG3))),
        ])
        .height(1)
    }).collect();

    let table = Table::new(
        field_rows,
        [Constraint::Length(14), Constraint::Percentage(40), Constraint::Min(0)],
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(" Packet Crafter ", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD))),
    )
    .style(Style::default().bg(C_BG));

    f.render_widget(table, area);

    let status_area = Rect {
        x: area.x + 1,
        y: area.y + area.height.saturating_sub(2),
        width: area.width.saturating_sub(2),
        height: 1,
    };
    // Flood status overrides result line when active
    let flood_line;
    let (status_text, status_color) = if app.craft.flooding {
        flood_line = format!(
            "● FLOODING  {}pps  sent:{}  [f] stop  [</>] rate  [C] reset",
            app.craft.flood_rate, app.craft.flood_sent
        );
        (flood_line.as_str(), C_RED)
    } else {
        match &app.craft.result {
            Some(Ok(msg))  => (msg.as_str(), C_GREEN),
            Some(Err(msg)) => (msg.as_str(), C_RED),
            None           => ("[Tab] next field  [Enter/e] edit  [Space/x] inject  [f] flood  [q] quit", C_FG3),
        }
    };
    f.render_widget(
        Paragraph::new(Span::styled(status_text, Style::default().fg(status_color))),
        status_area,
    );
}

fn draw_preview(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    let pkt_result = app.craft.build_packet(0);

    // ── Hex dump ────────────────────────────────────────────────────────────────
    let hex_lines: Vec<Line> = match &pkt_result {
        Ok(pkt) => pkt.bytes.chunks(16).enumerate().map(|(row, chunk)| {
            let offset = Span::styled(format!("{:04x}  ", row * 16), Style::default().fg(C_FG3));
            let hex_part: String = chunk.iter().map(|b| format!("{:02x} ", b)).collect();
            let padding  = " ".repeat((16 - chunk.len()) * 3);
            let ascii: String = chunk.iter()
                .map(|&b| if b >= 32 && b < 127 { b as char } else { '.' })
                .collect();
            Line::from(vec![
                offset,
                Span::styled(format!("{}{}", hex_part, padding), Style::default().fg(C_CYAN)),
                Span::styled(format!(" │{}", ascii), Style::default().fg(C_FG2)),
            ])
        }).collect(),
        Err(e) => vec![Line::from(Span::styled(format!("  Error: {}", e), Style::default().fg(C_RED)))],
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

    // ── Field summary ────────────────────────────────────────────────────────────
    let summary_lines: Vec<Line> = match &pkt_result {
        Ok(pkt) => {
            let proto = pkt.protocol.as_str();
            let is_tcp = matches!(proto, "TCP"|"HTTP"|"HTTPS"|"TLS"|"FTP"|"SSH"|"SMTP");
            let is_icmp = proto == "ICMP";

            // IP flags from byte 20
            let ip_fl_byte = if pkt.bytes.len() > 20 { pkt.bytes[20] } else { 0 };
            let ip_flags_str = fmt_ip_flags(ip_fl_byte);

            // L4 flags
            let l4_raw = app.craft.fields[crate::craft::F_L4_FL].value.trim();
            let l4_line: Line = if is_tcp {
                let fl = if pkt.bytes.len() > 47 { pkt.bytes[47] } else { parse_tcp_flags(l4_raw) };
                Line::from(vec![
                    Span::styled("  TCP Flags: ", Style::default().fg(C_FG2)),
                    Span::styled(
                        format!("{} (0x{:02x})", fmt_tcp_flags(fl), fl),
                        Style::default().fg(C_YELLOW),
                    ),
                ])
            } else if is_icmp {
                let (t, c) = parse_icmp_type_code(l4_raw);
                let name = icmp_name(t, c);
                Line::from(vec![
                    Span::styled("  ICMP:      ", Style::default().fg(C_FG2)),
                    Span::styled(
                        format!("type={} code={} ({})", t, c, name),
                        Style::default().fg(C_YELLOW),
                    ),
                ])
            } else {
                Line::from(vec![
                    Span::styled("  L4 Flags:  ", Style::default().fg(C_FG2)),
                    Span::styled("n/a", Style::default().fg(C_FG3)),
                ])
            };

            vec![
                Line::from(vec![
                    Span::styled("  Protocol:  ", Style::default().fg(C_FG2)),
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
                    Span::styled("  IP Flags:  ", Style::default().fg(C_FG2)),
                    Span::styled(
                        format!("{} (0x{:02x})", ip_flags_str, ip_fl_byte),
                        Style::default().fg(C_YELLOW),
                    ),
                ]),
                l4_line,
                Line::from(vec![
                    Span::styled("  Length:    ", Style::default().fg(C_FG2)),
                    Span::styled(format!("{} bytes", pkt.length), Style::default().fg(C_YELLOW)),
                ]),
                Line::from(vec![
                    Span::styled("  Info:      ", Style::default().fg(C_FG2)),
                    Span::styled(&pkt.info, Style::default().fg(C_FG)),
                ]),
                Line::from(vec![
                    Span::styled("  Flood:     ", Style::default().fg(C_FG2)),
                    Span::styled(
                        if app.craft.flooding {
                            format!("● {}pps  sent: {}", app.craft.flood_rate, app.craft.flood_sent)
                        } else {
                            format!("off  ({}pps when active)", app.craft.flood_rate)
                        },
                        if app.craft.flooding { Style::default().fg(C_RED).add_modifier(Modifier::BOLD) }
                        else { Style::default().fg(C_FG3) },
                    ),
                ]),
            ]
        }
        Err(e) => vec![Line::from(Span::styled(format!("  {}", e), Style::default().fg(C_RED)))],
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

// ─── Flag formatters ──────────────────────────────────────────────────────────

fn fmt_ip_flags(b: u8) -> String {
    if b == 0 { return "none".into(); }
    let mut out = String::new();
    if b & 0x40 != 0 { out.push_str("DF "); }
    if b & 0x20 != 0 { out.push_str("MF "); }
    out.trim_end().to_string()
}

fn fmt_tcp_flags(f: u8) -> String {
    if f == 0 { return "NONE".into(); }
    let mut out = String::new();
    if f & 0x01 != 0 { out.push_str("FIN "); }
    if f & 0x02 != 0 { out.push_str("SYN "); }
    if f & 0x04 != 0 { out.push_str("RST "); }
    if f & 0x08 != 0 { out.push_str("PSH "); }
    if f & 0x10 != 0 { out.push_str("ACK "); }
    if f & 0x20 != 0 { out.push_str("URG "); }
    if f & 0x40 != 0 { out.push_str("ECE "); }
    if f & 0x80 != 0 { out.push_str("CWR "); }
    out.trim_end().to_string()
}

fn icmp_name(t: u8, c: u8) -> &'static str {
    match (t, c) {
        (0, 0)  => "echo-reply",
        (3, 0)  => "net-unreachable",
        (3, 1)  => "host-unreachable",
        (3, 3)  => "port-unreachable",
        (5, _)  => "redirect",
        (8, 0)  => "echo-request",
        (11, 0) => "ttl-exceeded",
        (11, 1) => "frag-reassembly-exceeded",
        (13, 0) => "timestamp",
        (14, 0) => "timestamp-reply",
        _       => "unknown",
    }
}
