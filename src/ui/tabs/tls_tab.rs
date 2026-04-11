use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table},
};
use crate::app::App;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
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
        Cell::from("Flow").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("SNI").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Version").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Cipher").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("JA3 (truncated)").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("JA3s").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Flags").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
    ]).style(Style::default().bg(C_BG2)).height(1);

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
        let ja3 = s.ja3.as_deref()
            .map(|j| j[..j.len().min(16)].to_string())
            .unwrap_or_else(|| "-".into());
        let ja3s = s.ja3s.as_deref()
            .map(|j| j[..j.len().min(16)].to_string())
            .unwrap_or_else(|| "-".into());
        let flags = if s.is_weak() { "WEAK" } else { "ok" }.to_string();
        let flag_style = if s.is_weak() {
            Style::default().fg(C_RED).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_GREEN)
        };

        let row_style = if selected {
            Style::default().bg(C_BG2).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };

        Row::new(vec![
            Cell::from(s.flow_id.clone()).style(Style::default().fg(C_FG3)),
            Cell::from(sni).style(Style::default().fg(C_CYAN)),
            Cell::from(ver).style(Style::default().fg(C_FG2)),
            Cell::from(cipher).style(Style::default().fg(C_FG2)),
            Cell::from(ja3).style(Style::default().fg(C_FG3)),
            Cell::from(ja3s).style(Style::default().fg(C_FG3)),
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
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            format!(" TLS Intelligence — {} sessions ", sessions.len()),
            Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD),
        )))
    .style(Style::default().bg(C_BG));
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
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(" Session Detail ", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)));

    let Some(s) = sessions.get(app.tls_selected) else {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" No session selected.", Style::default().fg(C_FG3)),
            ])).block(block).style(Style::default().bg(C_BG)),
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
            Span::styled("  Flow:    ", Style::default().fg(C_FG3)),
            Span::styled(s.flow_id.clone(), Style::default().fg(C_CYAN)),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  SNI:     ", Style::default().fg(C_FG3)),
            Span::styled(s.sni.as_deref().unwrap_or("-"), Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD)),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  Version: ", Style::default().fg(C_FG3)),
            Span::styled(s.version_str(), Style::default().fg(C_FG2)),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  Cipher:  ", Style::default().fg(C_FG3)),
            Span::styled(
                s.cipher_suite
                    .map(|cs| format!("{} (0x{cs:04x})", crate::analysis::tls::cipher_name(cs)))
                    .unwrap_or_else(|| "-".into()),
                if s.is_weak() { Style::default().fg(C_RED).add_modifier(Modifier::BOLD) }
                else { Style::default().fg(C_GREEN) },
            ),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  JA3:     ", Style::default().fg(C_FG3)),
            Span::styled(s.ja3.as_deref().unwrap_or("-"), Style::default().fg(C_FG2)),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  JA3s:    ", Style::default().fg(C_FG3)),
            Span::styled(s.ja3s.as_deref().unwrap_or("-"), Style::default().fg(C_FG2)),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  Status:  ", Style::default().fg(C_FG3)),
            Span::styled(
                if s.is_weak() { "WEAK CIPHER" } else { "OK" },
                if s.is_weak() { Style::default().fg(C_RED).add_modifier(Modifier::BOLD) }
                else { Style::default().fg(C_GREEN) },
            ),
        ])),
    ];
    f.render_widget(
        List::new(left_items).style(Style::default().bg(C_BG)),
        cols[0],
    );

    // Right: cert info
    let right_items = vec![
        ListItem::new(Line::from(vec![
            Span::styled("  Cert CN:     ", Style::default().fg(C_FG3)),
            Span::styled(s.cert_cn.as_deref().unwrap_or("-"), Style::default().fg(C_CYAN)),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  Cert Issuer: ", Style::default().fg(C_FG3)),
            Span::styled(s.cert_issuer.as_deref().unwrap_or("-"), Style::default().fg(C_FG2)),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  Cert Expiry: ", Style::default().fg(C_FG3)),
            Span::styled(s.cert_not_after.as_deref().unwrap_or("-"), Style::default().fg(C_YELLOW)),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  SANs:        ", Style::default().fg(C_FG3)),
            Span::styled(
                if s.cert_san.is_empty() { "-".into() } else { s.cert_san.join(", ") },
                Style::default().fg(C_FG2),
            ),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  TLS Alert:   ", Style::default().fg(C_FG3)),
            Span::styled(
                match (s.alert_level, s.alert_desc) {
                    (Some(lvl), Some(desc)) => format!("level={lvl} desc={desc}"),
                    _ => "-".into(),
                },
                if s.alert_level == Some(2) { Style::default().fg(C_RED) }
                else { Style::default().fg(C_FG3) },
            ),
        ])),
    ];
    f.render_widget(
        List::new(right_items).style(Style::default().bg(C_BG)),
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
            format!(" {} sessions  {} with SNI  {} weak  [j/k] scroll  [c] clear",
                sessions.len(), with_sni, weak),
            Style::default().fg(C_FG3),
        ),
    ])).style(Style::default().bg(C_BG2));
    f.render_widget(bar, area);
}
