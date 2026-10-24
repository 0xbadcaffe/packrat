use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, List, ListItem, Paragraph, Row, Table, Wrap},
};

use crate::analysis::packet_fields::PacketField;
use crate::analysis::stream::ReassembledStream;
use crate::app::{AppView as App, InvestigationItem, InvestigationView};
use crate::model::evidence::{EvidenceRef, PacketRef};
use crate::net::flow::FlowKey;
use crate::net::packet::Packet;
use crate::ui::helpers::truncate;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    draw_context_header(f, app, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(30), Constraint::Min(0)])
        .split(chunks[1]);

    draw_worklist(f, app, body[0]);
    draw_active_view(f, app, body[1]);
}

fn draw_context_header(f: &mut Frame, app: &App, area: Rect) {
    let packet = app.active_investigation_packet();
    let title = packet
        .map(|pkt| {
            format!(
                " Packet #{}  {}  {} -> {}  len={}  Tray {}/{} ",
                pkt.no,
                pkt.protocol,
                pkt.src,
                pkt.dst,
                pkt.length,
                app.worklist.active.map(|index| index + 1).unwrap_or(0),
                app.worklist.items.len(),
            )
        })
        .unwrap_or_else(|| {
            app.worklist
                .active
                .and_then(|index| app.worklist.items.get(index))
                .map(|item| format!(" {} ", item.label()))
                .unwrap_or_else(|| " No item selected  Pin from a source view with m ".into())
        });

    let mut spans = vec![Span::styled(
        title,
        Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD),
    )];
    let navigation = if app.investigation_view == InvestigationView::Bytes {
        "h/l byte  j/k row  n/p packet  v live"
    } else {
        "n/p item  w tray  l live"
    };
    spans.push(Span::styled(
        format!(
            "  Screen: {}  [[/]] screen  {navigation}  = compare  , settings",
            app.investigation_view.label()
        ),
        Style::default().fg(C_FG3()),
    ));
    f.render_widget(
        Paragraph::new(Line::from(spans))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(C_BORDER())),
            )
            .style(Style::default().bg(C_BG())),
        area,
    );
}

fn draw_worklist(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .worklist
        .items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let selected = app.worklist.active == Some(index);
            let label = match item {
                InvestigationItem::Packet(packet_no) => app
                    .packet_by_no(*packet_no)
                    .map(packet_label)
                    .unwrap_or_else(|| format!("#{packet_no} missing")),
                _ => item.label(),
            };
            let style = if selected {
                Style::default()
                    .fg(C_BG())
                    .bg(C_CYAN())
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(C_FG())
            };
            ListItem::new(Line::from(vec![
                Span::styled(if selected { "> " } else { "  " }, style),
                Span::styled(label, style),
            ]))
            .style(if selected {
                Style::default().bg(C_CYAN())
            } else {
                Style::default().bg(C_BG())
            })
        })
        .collect();

    let content = if items.is_empty() {
        vec![ListItem::new(Line::from(vec![Span::styled(
            "No investigation items pinned.",
            Style::default().fg(C_FG3()),
        )]))]
    } else {
        items
    };
    let list = List::new(content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Plain)
                .border_style(Style::default().fg(if app.worklist.open {
                    C_CYAN()
                } else {
                    C_BORDER()
                }))
                .title(Span::styled(
                    " Investigation Tray ",
                    Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
                )),
        )
        .style(Style::default().bg(C_BG()));
    f.render_widget(list, area);
}

fn draw_active_view(f: &mut Frame, app: &App, area: Rect) {
    if app.investigation_view == InvestigationView::Transactions {
        transactions::draw(f, app, area);
        return;
    }
    let Some(packet) = app.active_investigation_packet() else {
        draw_artifact_context(f, app, area);
        return;
    };

    match app.investigation_view {
        InvestigationView::Summary => draw_summary(f, app, packet, area),
        InvestigationView::Decode => draw_headers(f, app, area),
        InvestigationView::Bytes => draw_bytes(f, app, packet, area),
        InvestigationView::Flow => draw_flow(f, app, packet, area),
        InvestigationView::Strings => draw_strings(f, app, packet, area),
        InvestigationView::Encrypted => draw_encrypted(f, app, packet, area),
        InvestigationView::Security => draw_security(f, app, packet, area),
        InvestigationView::Notes => draw_notes(f, app, packet, area),
        InvestigationView::Transactions => transactions::draw(f, app, area),
    }
}

fn draw_artifact_context(f: &mut Frame, app: &App, area: Rect) {
    let Some(context) = app.active_investigation_context() else {
        f.render_widget(
            Paragraph::new("No active investigation item.\n\nSelect context in a source view and press M to pin it.")
                .wrap(Wrap { trim: false })
                .block(panel("Investigation Context")),
            area,
        );
        return;
    };
    let mut lines = vec![
        Line::from(Span::styled(
            format!("{}: {}", context.kind, context.title),
            Style::default()
                .fg(if context.available { C_CYAN() } else { C_RED() })
                .add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
    ];
    for (label, value) in context.details {
        lines.push(Line::from(vec![
            Span::styled(
                format!("{label:<14}"),
                Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
            ),
            Span::styled(value, Style::default().fg(C_FG())),
        ]));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "n/p next or previous item  d remove  M pin current source context  Alt+Left back",
        Style::default().fg(C_FG3()),
    )));
    f.render_widget(
        Paragraph::new(scrolled(lines, app.investigation_scroll, area))
            .wrap(Wrap { trim: false })
            .block(panel("Context Inspector")),
        area,
    );
}

fn draw_summary(f: &mut Frame, app: &App, packet: &Packet, area: Rect) {
    let lines = vec![
        Line::from(vec![Span::styled(
            format!("Frame #{}", packet.no),
            Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD),
        )]),
        Line::from(format!("Time: {:.6}s", packet.timestamp)),
        Line::from(format!("Protocol: {}", packet.protocol)),
        Line::from(format!(
            "Source: {}{}",
            packet.src,
            packet.src_port.map(|p| format!(":{p}")).unwrap_or_default()
        )),
        Line::from(format!(
            "Destination: {}{}",
            packet.dst,
            packet.dst_port.map(|p| format!(":{p}")).unwrap_or_default()
        )),
        Line::from(format!("Length: {} bytes", packet.length)),
        Line::from(format!(
            "VLAN: {}",
            packet
                .vlan_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "none".into())
        )),
        Line::raw(""),
        Line::from(vec![Span::styled(
            "Info",
            Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
        )]),
        Line::from(packet.info.clone()),
        Line::raw(""),
        Line::from(vec![Span::styled(
            "Context",
            Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
        )]),
        Line::from(format!(
            "Visible packets: {} / total {}",
            app.filtered.len(),
            app.packets.len()
        )),
        Line::from(format!("Investigation items: {}", app.worklist.items.len())),
    ];
    f.render_widget(
        Paragraph::new(scrolled(lines, app.investigation_scroll, area))
            .block(panel("Summary"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn packet_label(packet: &Packet) -> String {
    format!(
        "#{} {} {} -> {}",
        packet.no,
        packet.protocol,
        truncate(&packet.src, 8),
        truncate(&packet.dst, 8)
    )
}

fn panel(title: &'static str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(C_BORDER()))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(C_GREEN()).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(C_BG()))
}

fn panel_owned(title: String) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(C_BORDER()))
        .title(Span::styled(
            title,
            Style::default().fg(C_GREEN()).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(C_BG()))
}

fn header_detail_lines(field: &PacketField) -> Vec<Line<'static>> {
    let offset = match (field.offset, field.length) {
        (Some(offset), Some(length)) => format!("offset {offset}, length {length}"),
        (Some(offset), None) => format!("offset {offset}"),
        _ => "offset unknown".into(),
    };
    vec![
        Line::from(vec![
            Span::styled(field.path.clone(), heading()),
            Span::raw(format!("  {}", field.label)),
        ]),
        Line::from(format!("Layer: {}   Value: {}", field.layer, field.value)),
        Line::from(format!(
            "{offset}   Use / to search paths or values, f to filter supported fields."
        )),
    ]
}

fn printable_bytes(bytes: &[u8], max: usize) -> String {
    bytes
        .iter()
        .take(max)
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}

fn heading() -> Style {
    Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD)
}

fn packet_flow_id(packet: &Packet) -> String {
    let sp = packet.src_port.unwrap_or(0);
    let dp = packet.dst_port.unwrap_or(0);
    let a = format!("{}:{}", packet.src, sp);
    let b = format!("{}:{}", packet.dst, dp);
    if a < b {
        format!("{a}-{b}")
    } else {
        format!("{b}-{a}")
    }
}

fn scrolled(lines: Vec<Line<'static>>, scroll: usize, area: Rect) -> Vec<Line<'static>> {
    let visible = area.height.saturating_sub(2) as usize;
    if visible == 0 || lines.len() <= visible {
        return lines;
    }
    let start = scroll.min(lines.len().saturating_sub(visible));
    lines.into_iter().skip(start).take(visible).collect()
}

mod decode;
use decode::*;
mod stream;
use stream::*;
mod findings;
use findings::*;
mod transactions;
mod transactions_http3;
