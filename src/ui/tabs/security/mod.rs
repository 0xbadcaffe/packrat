use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use crate::app::{AppView as App, SecuritySubTab};
use crate::net::security::Severity;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(0)])
        .split(area);

    draw_subtabs(f, app, chunks[0]);
    match app.security_tab {
        SecuritySubTab::Alerts => draw_alert_center(f, app, chunks[1]),
        SecuritySubTab::Ids => draw_ids(f, app, chunks[1]),
        SecuritySubTab::Credentials => draw_creds(f, app, chunks[1]),
        SecuritySubTab::OsFingerprint => draw_os(f, app, chunks[1]),
        SecuritySubTab::ArpWatch => draw_arp(f, app, chunks[1]),
        SecuritySubTab::DnsTunnel => draw_dns_tunnel(f, app, chunks[1]),
        SecuritySubTab::HttpAnalytics => draw_http(f, app, chunks[1]),
        SecuritySubTab::TlsWeakness => draw_tls(f, app, chunks[1]),
        SecuritySubTab::BruteForce => draw_brute(f, app, chunks[1]),
        SecuritySubTab::VulnHits => draw_vuln(f, app, chunks[1]),
        SecuritySubTab::IocHits => draw_ioc_hits(f, app, chunks[1]),
        SecuritySubTab::VlanIntel => draw_vlan_intel(f, app, chunks[1]),
        SecuritySubTab::ProcessScope => draw_process_scope(f, app, chunks[1]),
        SecuritySubTab::RoutePolicy => draw_route_policy(f, app, chunks[1]),
        SecuritySubTab::WirePulse => draw_wire_pulse(f, app, chunks[1]),
        SecuritySubTab::NetRegistry => draw_net_registry(f, app, chunks[1]),
        SecuritySubTab::Replay => draw_replay(f, app, chunks[1]),
    }
}

fn draw_subtabs(f: &mut Frame, app: &App, area: Rect) {
    let label = match app.security_tab {
        SecuritySubTab::Alerts => "Alert Center",
        SecuritySubTab::Ids => "IDS Alerts",
        SecuritySubTab::Credentials => "Credentials",
        SecuritySubTab::OsFingerprint => "OS Fingerprints",
        SecuritySubTab::ArpWatch => "ARP Watch",
        SecuritySubTab::DnsTunnel => "DNS Tunnels",
        SecuritySubTab::HttpAnalytics => "HTTP Analytics",
        SecuritySubTab::TlsWeakness => "TLS Weaknesses",
        SecuritySubTab::BruteForce => "Brute Force",
        SecuritySubTab::VulnHits => "Vulnerability Hits",
        SecuritySubTab::IocHits => "IOC Hits",
        SecuritySubTab::VlanIntel => "VLAN Intelligence",
        SecuritySubTab::ProcessScope => "SocketScope",
        SecuritySubTab::RoutePolicy => "RouteLedger",
        SecuritySubTab::WirePulse => "WirePulse",
        SecuritySubTab::NetRegistry => "NetRegistry",
        SecuritySubTab::Replay => "PCAP Replay",
    };
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" Defense / ", Style::default().fg(C_FG3())),
        Span::styled(
            label,
            Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "   [ / ] operational views   [a] alert center",
            Style::default().fg(C_FG2()),
        ),
    ]))
    .style(Style::default().bg(C_BG2()));
    f.render_widget(header, area);
}

fn draw_alert_center(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(6), Constraint::Length(7)])
        .split(area);
    let visible_indices = app.core.alert_center.visible_indices();
    let visible_rows = chunks[0].height.saturating_sub(3) as usize;
    let start = app.core.alert_center
        .selected
        .saturating_sub(visible_rows.saturating_sub(1));
    let header = Row::new(vec![
        cell_hdr("ID"),
        cell_hdr("Pkt"),
        cell_hdr("Severity"),
        cell_hdr("State"),
        cell_hdr("Hits"),
        cell_hdr("Priority"),
        cell_hdr("Source"),
        cell_hdr("Finding"),
    ])
    .height(1);
    let rows = visible_indices
        .iter()
        .skip(start)
        .take(visible_rows)
        .enumerate()
        .map(|(offset, index)| {
            let item = &app.core.alert_center.items[*index];
            let selected = start + offset == app.core.alert_center.selected;
            let severity_color = match item.severity.as_str() {
                "CRITICAL" | "CRIT" => C_RED(),
                "HIGH" => C_ORANGE(),
                "MEDIUM" | "WARN" => C_YELLOW(),
                _ => C_GREEN(),
            };
            Row::new(vec![
                Cell::from(item.id.to_string()),
                Cell::from(item.packet_no.to_string()),
                Cell::from(Span::styled(
                    &item.severity,
                    Style::default().fg(severity_color),
                )),
                Cell::from(item.disposition.to_string()),
                Cell::from(item.hit_count.to_string()),
                Cell::from(item.priority.to_string()),
                Cell::from(item.source.as_str()),
                Cell::from(item.title.as_str()),
            ])
            .style(if selected {
                Style::default().bg(C_SEL_BG()).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            })
        })
        .collect::<Vec<_>>();
    let title = format!(
        " Alert Center - {} findings - severity: {} - automation: {} ",
        visible_indices.len(),
        app.core.alert_center.severity_filter,
        app.core.alert_center.automation_mode,
    );
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(11),
            Constraint::Length(6),
            Constraint::Length(9),
            Constraint::Length(12),
            Constraint::Min(20),
        ],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG()));
    f.render_widget(table, chunks[0]);

    let detail = if let Some(item) = app.core.alert_center.selected_item() {
        vec![
            Line::from(vec![
                Span::styled(
                    format!("{} / {}", item.source, item.title),
                    Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(
                        "  {} hits, packets #{}..#{}",
                        item.hit_count, item.first_packet, item.last_packet
                    ),
                    Style::default().fg(C_FG3()),
                ),
            ]),
            Line::from(Span::styled(&item.detail, Style::default().fg(C_FG()))),
            Line::from(Span::styled(
                item.recommendation
                    .as_deref()
                    .unwrap_or("No automated recommendation; inspect and classify manually."),
                Style::default().fg(C_YELLOW()),
            )),
            Line::from(Span::styled(
                "Enter review  C confirm  z benign  K contained  x close  f filter  r simulate Guard",
                Style::default().fg(C_FG2()),
            )),
        ]
    } else {
        vec![Line::from(Span::styled(
            "No findings match the active filter.",
            Style::default().fg(C_FG3()),
        ))]
    };
    f.render_widget(
        Paragraph::new(detail)
            .block(block_titled(" Selected Finding "))
            .wrap(ratatui::widgets::Wrap { trim: true }),
        chunks[1],
    );
}

fn format_bytes(b: u64) -> String {
    if b >= 1_000_000_000 {
        format!("{:.1}G", b as f64 / 1e9)
    } else if b >= 1_000_000 {
        format!("{:.1}M", b as f64 / 1e6)
    } else if b >= 1_000 {
        format!("{:.1}K", b as f64 / 1e3)
    } else {
        format!("{}B", b)
    }
}

fn fmt_ts(ts: f64) -> String {
    if ts == 0.0 {
        return "—".into();
    }
    let secs = ts as u64;
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn cell_hdr(s: &str) -> Cell<'_> {
    Cell::from(Span::styled(
        s,
        Style::default().fg(C_FG3()).add_modifier(Modifier::BOLD),
    ))
}

fn block_titled(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER()))
        .title(Span::styled(
            title.to_string(),
            Style::default().fg(C_FG2()),
        ))
}

fn render_hint(f: &mut Frame, area: Rect, hint: &str) {
    let hint_area = Rect {
        x: area.x + 1,
        y: area.y + area.height.saturating_sub(1),
        width: area.width.saturating_sub(2),
        height: 1,
    };
    f.render_widget(
        Paragraph::new(Span::styled(hint, Style::default().fg(C_FG3()))),
        hint_area,
    );
}

// ─── IOC Hits ─────────────────────────────────────────────────────────────────

fn draw_ioc_hits(f: &mut Frame, app: &App, area: Rect) {
    let hits = &app.core.ioc_engine.hits;
    let scroll = app.security_scroll;

    let header = Row::new(vec![
        cell_hdr("Pkt#"),
        cell_hdr("Kind"),
        cell_hdr("IOC Value"),
        cell_hdr("Context"),
        cell_hdr("Description"),
    ])
    .height(1);

    let rows: Vec<Row> = hits
        .iter()
        .skip(scroll)
        .take(area.height.saturating_sub(4) as usize)
        .map(|h| {
            let kind_style = Style::default()
                .fg(match h.ioc.kind {
                    crate::analysis::ioc::IocKind::Ip => C_RED(),
                    crate::analysis::ioc::IocKind::Domain => C_ORANGE(),
                    crate::analysis::ioc::IocKind::Hash => C_YELLOW(),
                    crate::analysis::ioc::IocKind::Url => C_CYAN(),
                    crate::analysis::ioc::IocKind::Email => C_FG2(),
                })
                .add_modifier(Modifier::BOLD);
            Row::new(vec![
                Cell::from(format!("#{}", h.pkt_no)).style(Style::default().fg(C_FG3())),
                Cell::from(h.ioc.kind.to_string()).style(kind_style),
                Cell::from(h.ioc.value.clone()).style(Style::default().fg(C_RED())),
                Cell::from(h.context.clone()).style(Style::default().fg(C_CYAN())),
                Cell::from(h.ioc.description.clone()).style(Style::default().fg(C_FG2())),
            ])
        })
        .collect();

    let title = format!(
        " IOC Hits — {} hits  {} indicators loaded ",
        hits.len(),
        app.core.ioc_engine.ioc_count()
    );
    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(22),
            Constraint::Length(16),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG()));
    f.render_widget(table, area);

    render_hint(f, area, "[j/k] scroll  [I] reload IOC feeds  [C] clear");
}

mod sources;
use sources::*;
mod detections;
use detections::*;
mod vlan;
use vlan::*;
mod replay;
use replay::*;

mod vulnerabilities;
use vulnerabilities::*;
