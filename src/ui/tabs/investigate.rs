use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, List, ListItem, Paragraph, Row, Table, Wrap},
};

use crate::app::{App, InvestigationItem, InvestigationView};
use crate::analysis::packet_fields::PacketField;
use crate::analysis::stream::ReassembledStream;
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
            " Packet #{}  {}  {} -> {}  len={}  Tray {}/{} ",
            pkt.no,
            pkt.protocol,
            pkt.src,
            pkt.dst,
            pkt.length,
            app.worklist.active.map(|index| index + 1).unwrap_or(0),
            app.worklist.items.len(),
        )
    }).unwrap_or_else(|| {
        app.worklist.active
            .and_then(|index| app.worklist.items.get(index))
            .map(|item| format!(" {} ", item.label()))
            .unwrap_or_else(|| " No item selected  Pin from a source view with m ".into())
    });

    let mut spans = vec![Span::styled(title, Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD))];
    let navigation = if app.investigation_view == InvestigationView::Bytes {
        "h/l byte  j/k row  n/p packet  v live"
    } else {
        "n/p item  w tray  l live"
    };
    spans.push(Span::styled(
        format!("  Screen: {}  [[/]] screen  {navigation}  = compare  , settings", app.investigation_view.label()),
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
    let items: Vec<ListItem> = app.worklist.items.iter().enumerate().map(|(index, item)| {
        let selected = app.worklist.active == Some(index);
        let label = match item {
            InvestigationItem::Packet(packet_no) => app.packet_by_no(*packet_no)
                .map(packet_label).unwrap_or_else(|| format!("#{packet_no} missing")),
            _ => item.label(),
        };
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
            Span::styled("No investigation items pinned.", Style::default().fg(C_FG3())),
        ]))]
    } else {
        items
    };
    let list = List::new(content)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(if app.worklist.open { C_CYAN() } else { C_BORDER() }))
            .title(Span::styled(" Investigation Tray ", Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD))))
        .style(Style::default().bg(C_BG()));
    f.render_widget(list, area);
}

fn draw_active_view(f: &mut Frame, app: &App, area: Rect) {
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
            Style::default().fg(if context.available { C_CYAN() } else { C_RED() }).add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
    ];
    for (label, value) in context.details {
        lines.push(Line::from(vec![
            Span::styled(format!("{label:<14}"), Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
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
        Line::from(format!("Investigation items: {}", app.worklist.items.len())),
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
        " Headers  / search  j/k move  Enter bytes  f filter  c clear ".into()
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

fn draw_bytes(f: &mut Frame, app: &App, packet: &Packet, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(0)])
        .split(area);
    let bytes = &packet.bytes;
    let cursor = app.byte_cursor.min(bytes.len().saturating_sub(1));
    let byte = bytes.get(cursor).copied();
    let u16_be = bytes.get(cursor..cursor + 2)
        .map(|slice| u16::from_be_bytes([slice[0], slice[1]]));
    let u16_le = bytes.get(cursor..cursor + 2)
        .map(|slice| u16::from_le_bytes([slice[0], slice[1]]));
    let u32_be = bytes.get(cursor..cursor + 4)
        .map(|slice| u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]));
    let window_end = (cursor + 16).min(bytes.len());
    let entropy = if cursor < window_end {
        crate::net::inspector::shannon_entropy(&bytes[cursor..window_end])
    } else {
        0.0
    };
    let ascii = byte.map(|value| {
        if value.is_ascii_graphic() || value == b' ' { (value as char).to_string() } else { ".".into() }
    }).unwrap_or_else(|| "-".into());

    let interpretation = vec![
        Line::from(format!("Offset: {cursor} (0x{cursor:04x})  Packet: #{}  Length: {}", packet.no, bytes.len())),
        Line::from(format!(
            "u8: {}  i8: {}  bits: {}  ASCII: {ascii}",
            byte.map(|value| value.to_string()).unwrap_or_else(|| "-".into()),
            byte.map(|value| (value as i8).to_string()).unwrap_or_else(|| "-".into()),
            byte.map(|value| format!("{value:08b}")).unwrap_or_else(|| "-".into()),
        )),
        Line::from(format!(
            "u16 BE/LE: {} / {}  u32 BE: {}  entropy[next {}]: {entropy:.3}",
            u16_be.map(|value| value.to_string()).unwrap_or_else(|| "-".into()),
            u16_le.map(|value| value.to_string()).unwrap_or_else(|| "-".into()),
            u32_be.map(|value| value.to_string()).unwrap_or_else(|| "-".into()),
            window_end.saturating_sub(cursor),
        )),
    ];
    f.render_widget(
        Paragraph::new(interpretation)
            .block(panel("Byte Interpreter  h/l byte  j/k row  g/G ends"))
            .wrap(Wrap { trim: false }),
        chunks[0],
    );

    let visible_rows = chunks[1].height.saturating_sub(2) as usize;
    let selected_row = cursor / 16;
    let total_rows = bytes.len().div_ceil(16);
    let start_row = selected_row.saturating_sub(visible_rows.saturating_sub(1) / 2)
        .min(total_rows.saturating_sub(visible_rows));
    let mut lines = Vec::new();
    for row_index in start_row..(start_row + visible_rows).min(total_rows) {
        let offset = row_index * 16;
        let chunk = &bytes[offset..(offset + 16).min(bytes.len())];
        let mut spans = vec![Span::styled(format!("{offset:04x}  "), Style::default().fg(C_FG3()))];
        for index in 0..16 {
            if let Some(value) = chunk.get(index) {
                let absolute = offset + index;
                let style = if absolute == cursor {
                    Style::default().fg(C_BG()).bg(C_CYAN()).add_modifier(Modifier::BOLD)
                } else if value.is_ascii_graphic() {
                    Style::default().fg(C_GREEN())
                } else {
                    Style::default().fg(C_CYAN())
                };
                spans.push(Span::styled(format!("{value:02x}"), style));
                spans.push(Span::raw(if index == 7 { "  " } else { " " }));
            } else {
                spans.push(Span::raw(if index == 7 { "    " } else { "   " }));
            }
        }
        spans.push(Span::styled(" | ", Style::default().fg(C_FG3())));
        for (index, value) in chunk.iter().enumerate() {
            let absolute = offset + index;
            let character = if value.is_ascii_graphic() || *value == b' ' { *value as char } else { '.' };
            let style = if absolute == cursor {
                Style::default().fg(C_BG()).bg(C_CYAN()).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(C_FG2())
            };
            spans.push(Span::styled(character.to_string(), style));
        }
        lines.push(Line::from(spans));
    }
    f.render_widget(
        Paragraph::new(lines)
            .block(panel("Hex and ASCII  Enter on Headers jumps here")),
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

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(0)])
        .split(area);

    if rows.is_empty() {
        f.render_widget(
            Paragraph::new("No flow record exists for this packet yet.")
                .block(panel("Flow Context"))
                .wrap(Wrap { trim: false }),
            chunks[0],
        );
    } else {
        let table = Table::new(rows, [
            Constraint::Percentage(48),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(8),
        ]).header(Row::new(["Flow", "Proto", "Packets", "Bytes", "Beacon"]).style(Style::default().fg(C_FG2())))
            .block(panel("Flow Context"));
        f.render_widget(table, chunks[0]);
    }

    draw_stream_context(f, app, chunks[1]);
}

fn draw_stream_context(f: &mut Frame, app: &App, area: Rect) {
    let Some(stream) = app.active_investigation_stream() else {
        f.render_widget(
            Paragraph::new("No reassembled TCP stream is available for this packet.\n\nFor UDP protocols such as DTLS, use Headers for record fields and Security/Encrypted for context.")
                .block(panel("Stream Reassembly"))
                .wrap(Wrap { trim: false }),
            area,
        );
        return;
    };

    let mut lines = vec![
        Line::from(vec![Span::styled(stream.key.id(), heading())]),
        Line::from(format!(
            "Client bytes: {}   Server bytes: {}   Segments: {}   Closed: {}   s: follow stream",
            stream.client_data.len(),
            stream.server_data.len(),
            stream.segments.len(),
            stream.closed,
        )),
        Line::from(format!("First seen: {:.6}s   Last seen: {:.6}s", stream.first_seen, stream.last_seen)),
        Line::raw(""),
    ];
    lines.extend(stream_segment_lines(stream));
    f.render_widget(
        Paragraph::new(scrolled(lines, app.investigation_scroll, area))
            .block(panel("Stream Reassembly"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn stream_segment_lines(stream: &ReassembledStream) -> Vec<Line<'static>> {
    if stream.segments.is_empty() {
        return vec![Line::from("The stream exists, but no payload bytes have been reassembled yet.")];
    }

    stream.segments.iter().enumerate().map(|(index, segment)| {
        let data = if segment.from_client { &stream.client_data } else { &stream.server_data };
        let end = segment.offset.saturating_add(segment.length).min(data.len());
        let preview = if segment.offset < end {
            printable_bytes(&data[segment.offset..end], 96)
        } else {
            String::new()
        };
        let direction = if segment.from_client { "C->S" } else { "S->C" };
        let color = if segment.from_client { C_CYAN() } else { C_GREEN() };
        Line::from(vec![
            Span::styled(format!("{:>3} {} ", index + 1, direction), Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::styled(format!("{:.6}s len={}  ", segment.timestamp, segment.length), Style::default().fg(C_FG2())),
            Span::styled(preview, Style::default().fg(color)),
        ])
    }).collect()
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

fn printable_bytes(bytes: &[u8], max: usize) -> String {
    bytes.iter()
        .take(max)
        .map(|byte| if byte.is_ascii_graphic() || *byte == b' ' { *byte as char } else { '.' })
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
