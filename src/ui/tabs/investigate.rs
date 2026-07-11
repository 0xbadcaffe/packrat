use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, List, ListItem, Paragraph, Row, Table, Wrap},
};

use crate::app::{App, InvestigationView};
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
        InvestigationView::Decode | InvestigationView::Bytes => crate::ui::tabs::packets::draw_packet_detail(f, app, packet, area),
        InvestigationView::Flow => draw_flow(f, app, packet, area),
        InvestigationView::Strings => draw_strings(f, packet, area),
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
    f.render_widget(Paragraph::new(lines).block(panel("Summary")).wrap(Wrap { trim: false }), area);
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

fn draw_strings(f: &mut Frame, packet: &Packet, area: Rect) {
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
    f.render_widget(Paragraph::new(lines).block(panel("Packet Strings")).wrap(Wrap { trim: false }), area);
}

fn draw_encrypted(f: &mut Frame, app: &App, packet: &Packet, area: Rect) {
    let mut lines = vec![
        Line::from(format!("Protocol: {}", packet.protocol)),
        Line::from(format!("Known TLS sessions: {}", app.tls_tracker.len())),
        Line::from(format!("Known QUIC connections: {}", app.quic_scope.connections.len())),
    ];
    if packet.protocol.eq_ignore_ascii_case("TLS") || packet.protocol.eq_ignore_ascii_case("QUIC") {
        lines.push(Line::from("This packet is eligible for encrypted protocol inspection."));
    } else {
        lines.push(Line::from("This packet is not labeled TLS/QUIC."));
    }
    f.render_widget(Paragraph::new(lines).block(panel("Encrypted Context")).wrap(Wrap { trim: false }), area);
}

fn draw_security(f: &mut Frame, app: &App, packet: &Packet, area: Rect) {
    let lines = vec![
        Line::from(format!("IDS alerts: {}", app.security.ids_alerts.len())),
        Line::from(format!("Credential hits: {}", app.credentials.len())),
        Line::from(format!("IOC hits: {}", app.ioc_engine.hit_count())),
        Line::from(format!("Rule hits: {}", app.rule_engine.hits.len())),
        Line::raw(""),
        Line::from(format!("Packet endpoint pair: {} -> {}", packet.src, packet.dst)),
    ];
    f.render_widget(Paragraph::new(lines).block(panel("Security Context")).wrap(Wrap { trim: false }), area);
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
    f.render_widget(Paragraph::new(lines).block(panel("Packet Notes")).wrap(Wrap { trim: false }), area);
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
