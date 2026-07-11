use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table},
};
use crate::app::{App, EncryptedView};
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    if app.encrypted_view == EncryptedView::Quic {
        draw_quic(f, app, area);
        return;
    }
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(10), Constraint::Length(1)])
        .split(area);

    let sessions = app.tls_tracker.all();
    draw_session_table(f, app, &sessions, chunks[0]);
    draw_detail_panel(f, app, &sessions, chunks[1]);
    draw_status_bar(f, app, &sessions, chunks[2]);
}

fn draw_session_table(
    f: &mut Frame,
    app: &App,
    sessions: &[&crate::analysis::tls::TlsSession],
    area: Rect,
) {
    let header = Row::new(vec![
        Cell::from("Flow").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("SNI").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("Version").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("Cipher").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("JA4").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("JA3").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("Flags").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
    ]).style(Style::default().bg(C_BG2())).height(1);

    let visible_height = area.height.saturating_sub(3) as usize;
    let scroll_offset = if app.tls_selected < visible_height {
        0
    } else {
        app.tls_selected - visible_height + 1
    };

    let rows: Vec<Row> = sessions.iter().enumerate().skip(scroll_offset).map(|(idx, s)| {
        let selected = idx == app.tls_selected;
        let sni = s.sni.as_deref().unwrap_or("-").to_string();
        let ver = s.version_str().to_string();
        let cipher = s.cipher_suite
            .map(|cs| format!("{} (0x{cs:04x})", crate::analysis::tls::cipher_name(cs)))
            .unwrap_or_else(|| "-".into());
        let ja4 = s.ja4.as_deref()
            .map(|j| j[..j.len().min(16)].to_string())
            .unwrap_or_else(|| "-".into());
        let ja3 = s.ja3.as_deref()
            .map(|j| j[..j.len().min(16)].to_string())
            .unwrap_or_else(|| "-".into());
        let mut flags = Vec::new();
        if s.is_weak() { flags.push("WEAK"); }
        if s.ech_offered { flags.push("ECH"); }
        if s.key_material { flags.push("KEY"); }
        let flags = if flags.is_empty() { "ok".into() } else { flags.join(",") };
        let flag_style = if s.is_weak() {
            Style::default().fg(C_RED()).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_GREEN())
        };

        let row_style = if selected {
            Style::default().bg(C_BG2()).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };

        Row::new(vec![
            Cell::from(s.flow_id.clone()).style(Style::default().fg(C_FG3())),
            Cell::from(sni).style(Style::default().fg(C_CYAN())),
            Cell::from(ver).style(Style::default().fg(C_FG2())),
            Cell::from(cipher).style(Style::default().fg(C_FG2())),
            Cell::from(ja4).style(Style::default().fg(C_MAGENTA())),
            Cell::from(ja3).style(Style::default().fg(C_FG3())),
            Cell::from(flags).style(flag_style),
        ]).style(row_style)
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(30),
        Constraint::Length(28),
        Constraint::Length(10),
        Constraint::Length(32),
        Constraint::Length(18),
        Constraint::Length(18),
        Constraint::Length(6),
    ])
    .header(header)
    .block(Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER()))
        .title(Span::styled(
            format!(" TLS Intelligence — {} sessions ", sessions.len()),
            Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
        )))
    .style(Style::default().bg(C_BG()));
    f.render_widget(table, area);
}

fn draw_detail_panel(
    f: &mut Frame,
    app: &App,
    sessions: &[&crate::analysis::tls::TlsSession],
    area: Rect,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER()))
        .title(Span::styled(" Session Detail ", Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)));

    let Some(s) = sessions.get(app.tls_selected) else {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" No session selected.", Style::default().fg(C_FG3())),
            ])).block(block).style(Style::default().bg(C_BG())),
            area,
        );
        return;
    };

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)])
        .split(block.inner(area));
    f.render_widget(block, area);

    // Left: connection info
    let left_items = vec![
        ListItem::new(Line::from(vec![
            Span::styled("  Flow:    ", Style::default().fg(C_FG3())),
            Span::styled(s.flow_id.clone(), Style::default().fg(C_CYAN())),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  SNI:     ", Style::default().fg(C_FG3())),
            Span::styled(s.sni.as_deref().unwrap_or("-"), Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD)),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  Version: ", Style::default().fg(C_FG3())),
            Span::styled(s.version_str(), Style::default().fg(C_FG2())),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  Cipher:  ", Style::default().fg(C_FG3())),
            Span::styled(
                s.cipher_suite
                    .map(|cs| format!("{} (0x{cs:04x})", crate::analysis::tls::cipher_name(cs)))
                    .unwrap_or_else(|| "-".into()),
                if s.is_weak() { Style::default().fg(C_RED()).add_modifier(Modifier::BOLD) }
                else { Style::default().fg(C_GREEN()) },
            ),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  JA4:     ", Style::default().fg(C_FG3())),
            Span::styled(s.ja4.as_deref().unwrap_or("-"), Style::default().fg(C_MAGENTA())),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  JA3:     ", Style::default().fg(C_FG3())),
            Span::styled(s.ja3.as_deref().unwrap_or("-"), Style::default().fg(C_FG2())),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  JA3s:    ", Style::default().fg(C_FG3())),
            Span::styled(s.ja3s.as_deref().unwrap_or("-"), Style::default().fg(C_FG2())),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  ALPN:    ", Style::default().fg(C_FG3())),
            Span::styled(s.alpn.as_deref().unwrap_or("-"), Style::default().fg(C_CYAN())),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  Status:  ", Style::default().fg(C_FG3())),
            Span::styled(
                if s.ech_offered { "ECH OFFERED" } else if s.is_weak() { "WEAK CIPHER" } else { "OK" },
                if s.is_weak() { Style::default().fg(C_RED()).add_modifier(Modifier::BOLD) }
                else { Style::default().fg(C_GREEN()) },
            ),
        ])),
    ];
    f.render_widget(
        List::new(left_items).style(Style::default().bg(C_BG())),
        cols[0],
    );

    // Right: cert info
    let right_items = vec![
        ListItem::new(Line::from(vec![
            Span::styled("  Cert CN:     ", Style::default().fg(C_FG3())),
            Span::styled(s.cert_cn.as_deref().unwrap_or("-"), Style::default().fg(C_CYAN())),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  Cert Issuer: ", Style::default().fg(C_FG3())),
            Span::styled(s.cert_issuer.as_deref().unwrap_or("-"), Style::default().fg(C_FG2())),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  Cert Expiry: ", Style::default().fg(C_FG3())),
            Span::styled(s.cert_not_after.as_deref().unwrap_or("-"), Style::default().fg(C_YELLOW())),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  SANs:        ", Style::default().fg(C_FG3())),
            Span::styled(
                if s.cert_san.is_empty() { "-".into() } else { s.cert_san.join(", ") },
                Style::default().fg(C_FG2()),
            ),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  Key Material: ", Style::default().fg(C_FG3())),
            Span::styled(
                if s.key_material { "available (record decoder required)" } else { "not available" },
                Style::default().fg(if s.key_material { C_GREEN() } else { C_FG3() }),
            ),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  TLS Alert:   ", Style::default().fg(C_FG3())),
            Span::styled(
                match (s.alert_level, s.alert_desc) {
                    (Some(lvl), Some(desc)) => format!("level={lvl} desc={desc}"),
                    _ => "-".into(),
                },
                if s.alert_level == Some(2) { Style::default().fg(C_RED()) }
                else { Style::default().fg(C_FG3()) },
            ),
        ])),
    ];
    f.render_widget(
        List::new(right_items).style(Style::default().bg(C_BG())),
        cols[1],
    );
}

fn draw_status_bar(
    f: &mut Frame,
    _app: &App,
    sessions: &[&crate::analysis::tls::TlsSession],
    area: Rect,
) {
    let weak = sessions.iter().filter(|s| s.is_weak()).count();
    let with_sni = sessions.iter().filter(|s| s.sni.is_some()).count();
    let bar = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" TLS view  {} sessions  {} SNI  {} weak  {} keys  [[/]] TLS/QUIC  [j/k] scroll",
                sessions.len(), with_sni, weak, _app.tls_tracker.key_shelf.secret_count()),
            Style::default().fg(C_FG3()),
        ),
    ])).style(Style::default().bg(C_BG2()));
    f.render_widget(bar, area);
}

fn draw_quic(f: &mut Frame, app: &App, area: Rect) {
    let connections = app.quic_scope.all();
    let header = Row::new(vec![
        Cell::from("Connection ID"), Cell::from("Version"), Cell::from("Types"),
        Cell::from("Packets"), Cell::from("Bytes"), Cell::from("Addresses"), Cell::from("Flags"),
    ]).style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD));
    let rows = connections.iter().map(|connection| {
        let mut types: Vec<_> = connection.packet_types.iter().cloned().collect();
        types.sort();
        let flags = [
            (!connection.fixed_bit_valid).then_some("INVALID-FIXED"),
            connection.migration_observed().then_some("MIGRATION"),
        ].into_iter().flatten().collect::<Vec<_>>().join(",");
        Row::new(vec![
            Cell::from(connection.id.clone()).style(Style::default().fg(C_CYAN())),
            Cell::from(connection.version.map(|version| format!("0x{version:08x}")).unwrap_or_else(|| "short".into())),
            Cell::from(types.join(",")),
            Cell::from(connection.packets.to_string()),
            Cell::from(crate::ui::fmt_bytes(connection.bytes)),
            Cell::from(connection.addresses.len().to_string()),
            Cell::from(flags).style(Style::default().fg(C_RED())),
        ])
    }).collect::<Vec<_>>();
    let chunks = Layout::default().direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)]).split(area);
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [Constraint::Length(24), Constraint::Length(12), Constraint::Length(24),
         Constraint::Length(10), Constraint::Length(12), Constraint::Length(10), Constraint::Min(0)],
    ).block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(C_BORDER()))
        .title(Span::styled(format!(" QUIC Scope - {} connections ", connections.len()), Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD))))
        .style(Style::default().bg(C_BG()));
    f.render_widget(table, chunks[0]);
    f.render_widget(Paragraph::new(" QUIC invariant headers only; protected payload is never presented as decoded  [[/]] TLS/QUIC")
        .style(Style::default().fg(C_FG3()).bg(C_BG2())), chunks[1]);
}
