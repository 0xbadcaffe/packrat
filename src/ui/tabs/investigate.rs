use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, List, ListItem, Paragraph, Row, Table, Wrap},
};

use crate::app::{App, InvestigationView};
use crate::analysis::packet_fields::PacketField;
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
    let title = packet.map(|pkt| {
        format!(
            " Packet #{}  {}  {} -> {}  len={}  Worklist {}/{} ",
            pkt.no,
            pkt.protocol,
            pkt.src,
            pkt.dst,
            pkt.length,
            app.worklist.active.map(|index| index + 1).unwrap_or(0),
            app.worklist.packet_nos.len(),
        )
    }).unwrap_or_else(|| " No packet selected  Add from Live with m, open with Enter ".into());

    let mut spans = vec![Span::styled(title, Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD))];
    spans.push(Span::styled(
        format!("  Screen: {}  [[/]] screen  n/p packet  w worklist  l live  , settings", app.investigation_view.label()),
        Style::default().fg(C_FG3()),
    ));
    f.render_widget(
        Paragraph::new(Line::from(spans))
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(C_BORDER())))
            .style(Style::default().bg(C_BG())),
        area,
    );
}

fn draw_worklist(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app.worklist.packet_nos.iter().enumerate().map(|(index, packet_no)| {
        let selected = app.worklist.active == Some(index);
        let packet = app.packet_by_no(*packet_no);
        let label = packet.map(packet_label).unwrap_or_else(|| format!("#{packet_no} missing"));
        let style = if selected {
            Style::default().fg(C_BG()).bg(C_CYAN()).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_FG())
        };
        ListItem::new(Line::from(vec![
            Span::styled(if selected { "> " } else { "  " }, style),
            Span::styled(label, style),
        ])).style(if selected { Style::default().bg(C_CYAN()) } else { Style::default().bg(C_BG()) })
    }).collect();

    let content = if items.is_empty() {
        vec![ListItem::new(Line::from(vec![
            Span::styled("No packets marked.", Style::default().fg(C_FG3())),
        ]))]
    } else {
        items
    };
    let list = List::new(content)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(if app.worklist.open { C_CYAN() } else { C_BORDER() }))
            .title(Span::styled(" Worklist ", Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD))))
        .style(Style::default().bg(C_BG()));
    f.render_widget(list, area);
}

fn draw_active_view(f: &mut Frame, app: &App, area: Rect) {
    let Some(packet) = app.active_investigation_packet() else {
        let empty = Paragraph::new("No active packet.\n\nGo to Live packets, select a packet, then press m to mark it or Enter to investigate it.")
            .wrap(Wrap { trim: false })
            .block(panel("Investigation"));
        f.render_widget(empty, area);
        return;
    };

    match app.investigation_view {
        InvestigationView::Summary => draw_summary(f, app, packet, area),
        InvestigationView::Decode => draw_headers(f, app, area),
        InvestigationView::Bytes => crate::ui::tabs::packets::draw_packet_detail(f, app, packet, area),
        InvestigationView::Flow => draw_flow(f, app, packet, area),
        InvestigationView::Strings => draw_strings(f, app, packet, area),
        InvestigationView::Encrypted => draw_encrypted(f, app, packet, area),
        InvestigationView::Security => draw_security(f, app, packet, area),
        InvestigationView::Notes => draw_notes(f, app, packet, area),
    }
}

fn draw_summary(f: &mut Frame, app: &App, packet: &Packet, area: Rect) {
    let lines = vec![
        Line::from(vec![Span::styled(format!("Frame #{}", packet.no), Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD))]),
        Line::from(format!("Time: {:.6}s", packet.timestamp)),
        Line::from(format!("Protocol: {}", packet.protocol)),
        Line::from(format!("Source: {}{}", packet.src, packet.src_port.map(|p| format!(":{p}")).unwrap_or_default())),
        Line::from(format!("Destination: {}{}", packet.dst, packet.dst_port.map(|p| format!(":{p}")).unwrap_or_default())),
        Line::from(format!("Length: {} bytes", packet.length)),
        Line::from(format!("VLAN: {}", packet.vlan_id.map(|id| id.to_string()).unwrap_or_else(|| "none".into()))),
        Line::raw(""),
        Line::from(vec![Span::styled("Info", Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD))]),
        Line::from(packet.info.clone()),
        Line::raw(""),
        Line::from(vec![Span::styled("Context", Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD))]),
        Line::from(format!("Visible packets: {} / total {}", app.filtered.len(), app.packets.len())),
        Line::from(format!("Worklist packets: {}", app.worklist.packet_nos.len())),
    ];
    f.render_widget(Paragraph::new(scrolled(lines, app.investigation_scroll, area)).block(panel("Summary")).wrap(Wrap { trim: false }), area);
}

fn draw_headers(f: &mut Frame, app: &App, area: Rect) {
    let fields = app.visible_packet_header_fields();
    let selected = app.header_cursor.min(fields.len().saturating_sub(1));
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(5)])
        .split(area);

    let visible_rows = chunks[0].height.saturating_sub(3) as usize;
    let start = if visible_rows == 0 {
        0
    } else if selected >= visible_rows {
        selected + 1 - visible_rows
    } else {
        0
    };

    let rows: Vec<Row> = fields.iter().enumerate().skip(start).take(visible_rows.max(1)).map(|(index, field)| {
        let style = if index == selected {
            Style::default().fg(C_BG()).bg(C_CYAN()).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_FG())
        };
        Row::new(vec![
            Cell::from(field.layer.clone()),
            Cell::from(field.path.clone()),
            Cell::from(field.label.clone()),
            Cell::from(field.value.clone()),
        ]).style(style)
    }).collect();

    let title = if app.header_searching {
        format!(" Headers  search: {}_ ", app.header_search)
    } else if app.header_search.is_empty() {
        " Headers  / search  j/k move  f filter  c clear search ".into()
    } else {
        format!(" Headers  filter: {}  / edit  c clear ", app.header_search)
    };

    let table = Table::new(rows, [
        Constraint::Length(12),
        Constraint::Length(24),
        Constraint::Length(24),
        Constraint::Min(12),
    ])
    .header(Row::new(["Layer", "Path", "Field", "Value"]).style(Style::default().fg(C_FG2()).add_modifier(Modifier::BOLD)))
    .block(panel_owned(title));
    f.render_widget(table, chunks[0]);

    let detail = fields.get(selected)
        .map(header_detail_lines)
        .unwrap_or_else(|| vec![
            Line::from("No header fields match the current search."),
            Line::from("Press c to clear search or / to enter a new query."),
        ]);
    f.render_widget(
        Paragraph::new(detail)
            .block(panel("Selected Field"))
            .wrap(Wrap { trim: false }),
        chunks[1],
    );
}

fn draw_flow(f: &mut Frame, app: &App, packet: &Packet, area: Rect) {
    let key = FlowKey::from_packet(packet);
    let rows: Vec<Row> = app.flow_tracker.sorted_flows(&app.flows_sort).into_iter()
        .filter(|flow| flow.key == key)
        .map(|flow| Row::new(vec![
            Cell::from(format!("{}:{} <-> {}:{}", flow.key.ep1.0, flow.key.ep1.1, flow.key.ep2.0, flow.key.ep2.1)),
            Cell::from(flow.key.proto.clone()),
            Cell::from(flow.packets.to_string()),
            Cell::from(flow.bytes.to_string()),
            Cell::from(format!("{:.1}", flow.beacon_score)),
        ]))
        .collect();
    if rows.is_empty() {
        f.render_widget(
            Paragraph::new("No flow record exists for this packet yet.")
                .block(panel("Flow Context"))
                .wrap(Wrap { trim: false }),
            area,
        );
        return;
    }
    let table = Table::new(rows, [
        Constraint::Percentage(48),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(8),
    ]).header(Row::new(["Flow", "Proto", "Packets", "Bytes", "Beacon"]).style(Style::default().fg(C_FG2())))
        .block(panel("Flow Context"));
    f.render_widget(table, area);
}

fn draw_strings(f: &mut Frame, app: &App, packet: &Packet, area: Rect) {
    let mut lines = Vec::new();
    let mut run = Vec::new();
    for byte in &packet.bytes {
        if byte.is_ascii_graphic() || *byte == b' ' {
            run.push(*byte);
        } else if run.len() >= 4 {
            lines.push(Line::from(String::from_utf8_lossy(&run).to_string()));
            run.clear();
        } else {
            run.clear();
        }
    }
    if run.len() >= 4 {
        lines.push(Line::from(String::from_utf8_lossy(&run).to_string()));
    }
    if lines.is_empty() {
        lines.push(Line::from("No printable strings of length >= 4."));
    }
    f.render_widget(Paragraph::new(scrolled(lines, app.investigation_scroll, area)).block(panel("Packet Strings")).wrap(Wrap { trim: false }), area);
}

fn draw_encrypted(f: &mut Frame, app: &App, packet: &Packet, area: Rect) {
    let mut lines = vec![
        Line::from(format!("Protocol: {}", packet.protocol)),
        Line::from(format!("Known TLS sessions: {}", app.tls_tracker.len())),
        Line::from(format!("Known QUIC connections: {}", app.quic_scope.connections.len())),
    ];
    if let Some(session) = app.tls_tracker.get(&packet_flow_id(packet)) {
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![Span::styled("TLS session", heading())]));
        lines.push(Line::from(format!("Flow: {}", session.flow_id)));
        lines.push(Line::from(format!("Version: {}", session.tls_version.as_deref().unwrap_or("unknown"))));
        lines.push(Line::from(format!("SNI: {}", session.sni.as_deref().unwrap_or("none"))));
        lines.push(Line::from(format!("ALPN: {}", session.alpn.as_deref().unwrap_or("none"))));
        lines.push(Line::from(format!("JA4: {}", session.ja4.as_deref().unwrap_or("none"))));
        lines.push(Line::from(format!("Key material: {}", if session.key_material { "available" } else { "not available" })));
        for record in session.decrypted_records.iter().filter(|record| record.packet_no == packet.no) {
            lines.push(Line::from(format!("Decoded: {} {} bytes - {}", record.content_type, record.plaintext.len(), record.detail)));
        }
    }
    for connection in app.quic_scope.connections.values() {
        let frames: Vec<_> = connection.decoded_frames.iter().filter(|frame| frame.packet_no == packet.no).collect();
        if !frames.is_empty() || connection.addresses.contains(&packet.src) || connection.addresses.contains(&packet.dst) {
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![Span::styled("QUIC connection", heading())]));
            lines.push(Line::from(format!("ID: {}", connection.id)));
            lines.push(Line::from(format!("Version: {}", connection.version.map(|v| format!("{v:08x}")).unwrap_or_else(|| "short".into()))));
            lines.push(Line::from(format!("RATQ: {}", connection.ratq)));
            for frame in frames {
                lines.push(Line::from(format!("Decoded frame: {} - {}", frame.frame_type, frame.detail)));
            }
        }
    }
    if lines.len() == 3 {
        lines.push(Line::raw(""));
        lines.push(Line::from("No TLS/QUIC session context is tied to this packet yet."));
    }
    f.render_widget(Paragraph::new(scrolled(lines, app.investigation_scroll, area)).block(panel("Encrypted Context")).wrap(Wrap { trim: false }), area);
}

fn draw_security(f: &mut Frame, app: &App, packet: &Packet, area: Rect) {
    let mut lines = vec![
        Line::from(vec![Span::styled(format!("Packet #{} security context", packet.no), heading())]),
        Line::from(format!("Endpoint pair: {} -> {}", packet.src, packet.dst)),
        Line::raw(""),
    ];

    let mut count = 0usize;
    for alert in app.security.ids_alerts.iter().filter(|alert| alert.pkt_no == packet.no) {
        count += 1;
        lines.push(Line::from(format!("IDS {} {} - {}", alert.severity, alert.signature, alert.detail)));
    }
    for hit in app.security.vuln_hits.iter().filter(|hit| hit.pkt_no == packet.no) {
        count += 1;
        lines.push(Line::from(format!("VULN {} - {}", hit.kind, hit.detail)));
    }
    for hit in app.security.tls_weaknesses.iter().filter(|hit| hit.pkt_no == packet.no) {
        count += 1;
        lines.push(Line::from(format!("TLS {} - {}", hit.kind, hit.detail)));
    }
    for hit in app.ioc_engine.hits.iter().filter(|hit| hit.pkt_no == packet.no) {
        count += 1;
        lines.push(Line::from(format!("IOC {} {} via {}", hit.ioc.kind, hit.ioc.value, hit.context)));
    }
    for hit in app.rule_engine.hits.iter().filter(|hit| hit.pkt_no == packet.no) {
        count += 1;
        lines.push(Line::from(format!("RULE {} - {}", hit.rule_name, hit.message)));
    }
    for cred in app.credentials.iter().filter(|cred| cred.pkt_no == packet.no) {
        count += 1;
        lines.push(Line::from(format!("CRED {} {} = {}", cred.proto, cred.kind, cred.value)));
    }
    if count == 0 {
        lines.push(Line::from("No packet-specific security findings recorded."));
    }
    f.render_widget(Paragraph::new(scrolled(lines, app.investigation_scroll, area)).block(panel("Security Context")).wrap(Wrap { trim: false }), area);
}

fn draw_notes(f: &mut Frame, app: &App, packet: &Packet, area: Rect) {
    let evidence = EvidenceRef::Packet(PacketRef(packet.no));
    let notes = app.notebook.for_evidence(&evidence);
    let lines = if notes.is_empty() {
        vec![Line::from("No notes linked to this packet yet.")]
    } else {
        notes.into_iter()
            .map(|note| Line::from(format!("#{} {}", note.id, note.text)))
            .collect()
    };
    f.render_widget(Paragraph::new(scrolled(lines, app.investigation_scroll, area)).block(panel("Packet Notes")).wrap(Wrap { trim: false }), area);
}

fn packet_label(packet: &Packet) -> String {
    format!("#{} {} {} -> {}", packet.no, packet.protocol, truncate(&packet.src, 8), truncate(&packet.dst, 8))
}

fn panel(title: &'static str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(C_BORDER()))
        .title(Span::styled(format!(" {title} "), Style::default().fg(C_GREEN()).add_modifier(Modifier::BOLD)))
        .style(Style::default().bg(C_BG()))
}

fn panel_owned(title: String) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(C_BORDER()))
        .title(Span::styled(title, Style::default().fg(C_GREEN()).add_modifier(Modifier::BOLD)))
        .style(Style::default().bg(C_BG()))
}

fn header_detail_lines(field: &PacketField) -> Vec<Line<'static>> {
    let offset = match (field.offset, field.length) {
        (Some(offset), Some(length)) => format!("offset {offset}, length {length}"),
        (Some(offset), None) => format!("offset {offset}"),
        _ => "offset unknown".into(),
    };
    vec![
        Line::from(vec![Span::styled(field.path.clone(), heading()), Span::raw(format!("  {}", field.label))]),
        Line::from(format!("Layer: {}   Value: {}", field.layer, field.value)),
        Line::from(format!("{offset}   Use / to search paths or values, f to filter supported fields.")),
    ]
}

fn heading() -> Style {
    Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD)
}

fn packet_flow_id(packet: &Packet) -> String {
    let sp = packet.src_port.unwrap_or(0);
    let dp = packet.dst_port.unwrap_or(0);
    let a = format!("{}:{}", packet.src, sp);
    let b = format!("{}:{}", packet.dst, dp);
    if a < b { format!("{a}-{b}") } else { format!("{b}-{a}") }
}

fn scrolled(lines: Vec<Line<'static>>, scroll: usize, area: Rect) -> Vec<Line<'static>> {
    let visible = area.height.saturating_sub(2) as usize;
    if visible == 0 || lines.len() <= visible {
        return lines;
    }
    let start = scroll.min(lines.len().saturating_sub(visible));
    lines.into_iter().skip(start).take(visible).collect()
}
