use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs},
};

use crate::app::{App, SecuritySubTab};
use crate::net::security::Severity;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(0)])
        .split(area);

    draw_subtabs(f, app, chunks[0]);
    match app.security_tab {
        SecuritySubTab::Ids          => draw_ids(f, app, chunks[1]),
        SecuritySubTab::Credentials  => draw_creds(f, app, chunks[1]),
        SecuritySubTab::OsFingerprint=> draw_os(f, app, chunks[1]),
        SecuritySubTab::ArpWatch     => draw_arp(f, app, chunks[1]),
        SecuritySubTab::DnsTunnel    => draw_dns_tunnel(f, app, chunks[1]),
        SecuritySubTab::HttpAnalytics=> draw_http(f, app, chunks[1]),
        SecuritySubTab::TlsWeakness  => draw_tls(f, app, chunks[1]),
        SecuritySubTab::BruteForce   => draw_brute(f, app, chunks[1]),
        SecuritySubTab::VulnHits     => draw_vuln(f, app, chunks[1]),
        SecuritySubTab::IocHits      => draw_ioc_hits(f, app, chunks[1]),
        SecuritySubTab::Replay       => draw_replay(f, app, chunks[1]),
    }
}

fn draw_subtabs(f: &mut Frame, app: &App, area: Rect) {
    let labels = [
        "IDS", "Credentials", "OS Fingerprint", "ARP Watch",
        "DNS Tunnel", "HTTP", "TLS", "Brute Force", "Vulns", "IOC Hits", "Replay",
    ];
    let idx = match app.security_tab {
        SecuritySubTab::Ids           => 0,
        SecuritySubTab::Credentials   => 1,
        SecuritySubTab::OsFingerprint => 2,
        SecuritySubTab::ArpWatch      => 3,
        SecuritySubTab::DnsTunnel     => 4,
        SecuritySubTab::HttpAnalytics => 5,
        SecuritySubTab::TlsWeakness   => 6,
        SecuritySubTab::BruteForce    => 7,
        SecuritySubTab::VulnHits      => 8,
        SecuritySubTab::IocHits       => 9,
        SecuritySubTab::Replay        => 10,
    };
    let titles: Vec<Line> = labels.iter().map(|l| Line::from(*l)).collect();
    let tabs = Tabs::new(titles)
        .select(idx)
        .style(Style::default().fg(C_FG3).bg(C_BG2))
        .highlight_style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD))
        .divider("│")
        .block(Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(C_BORDER)));
    f.render_widget(tabs, area);
}

// ─── IDS Alerts ──────────────────────────────────────────────────────────────

fn draw_ids(f: &mut Frame, app: &App, area: Rect) {
    let alerts = &app.security.ids_alerts;
    let scroll = app.security_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![
        cell_hdr("Pkt#"), cell_hdr("Severity"), cell_hdr("Signature"), cell_hdr("Detail"),
    ]).height(1);

    let rows: Vec<Row> = alerts.iter().skip(scroll).take(visible).map(|a| {
        let sev_color = match a.severity {
            Severity::Critical => C_RED,
            Severity::High     => Color::Rgb(215, 135, 0),
            Severity::Medium   => C_YELLOW,
            Severity::Low      => C_GREEN,
        };
        Row::new(vec![
            Cell::from(Span::styled(a.pkt_no.to_string(), Style::default().fg(C_FG3))),
            Cell::from(Span::styled(a.severity.to_string(), Style::default().fg(sev_color))),
            Cell::from(Span::styled(a.signature, Style::default().fg(C_CYAN))),
            Cell::from(Span::styled(&a.detail, Style::default().fg(C_FG))),
        ]).height(1)
    }).collect();

    let count_str = format!(" IDS Alerts ({}) ", alerts.len());
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [Constraint::Length(7), Constraint::Length(10), Constraint::Length(28), Constraint::Min(0)],
    )
    .block(block_titled(&count_str))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, area);
    render_hint(f, area, "[Tab/[/]] sub-tab  [j/k] scroll  [C] clear  [q] quit");
}

// ─── Credentials ─────────────────────────────────────────────────────────────

fn draw_creds(f: &mut Frame, app: &App, area: Rect) {
    let creds = &app.credentials;
    let scroll = app.security_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![
        cell_hdr("Pkt#"), cell_hdr("Type"), cell_hdr("Value"),
    ]).height(1);

    let rows: Vec<Row> = creds.iter().skip(scroll).take(visible).map(|c| {
        Row::new(vec![
            Cell::from(Span::styled(c.pkt_no.to_string(), Style::default().fg(C_FG3))),
            Cell::from(Span::styled(c.kind, Style::default().fg(C_YELLOW))),
            Cell::from(Span::styled(&c.value, Style::default().fg(C_RED))),
        ]).height(1)
    }).collect();

    let title = format!(" Cleartext Credentials ({}) ", creds.len());
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [Constraint::Length(7), Constraint::Length(18), Constraint::Min(0)],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, area);
    render_hint(f, area, "Cleartext credentials detected in captured traffic");
}

// ─── OS Fingerprint ──────────────────────────────────────────────────────────

fn draw_os(f: &mut Frame, app: &App, area: Rect) {
    let guesses = &app.security.os_guesses;
    let scroll = app.security_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![
        cell_hdr("IP Address"), cell_hdr("OS Guess"), cell_hdr("TTL"), cell_hdr("Window"),
    ]).height(1);

    let rows: Vec<Row> = guesses.iter().skip(scroll).take(visible).map(|g| {
        Row::new(vec![
            Cell::from(Span::styled(&g.src_ip, Style::default().fg(C_CYAN))),
            Cell::from(Span::styled(g.os, Style::default().fg(C_FG))),
            Cell::from(Span::styled(g.ttl.to_string(), Style::default().fg(C_FG2))),
            Cell::from(Span::styled(g.window.to_string(), Style::default().fg(C_FG2))),
        ]).height(1)
    }).collect();

    let title = format!(" OS Fingerprints ({} hosts) ", guesses.len());
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [Constraint::Length(18), Constraint::Length(30), Constraint::Length(6), Constraint::Min(0)],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, area);
    render_hint(f, area, "Passive OS detection from TTL and TCP window size");
}

// ─── ARP Watch ───────────────────────────────────────────────────────────────

fn draw_arp(f: &mut Frame, app: &App, area: Rect) {
    let anomalies = &app.security.arp_anomalies;
    let scroll = app.security_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![
        cell_hdr("IP"), cell_hdr("Old MAC"), cell_hdr("New MAC"), cell_hdr("Pkt#"),
    ]).height(1);

    let rows: Vec<Row> = anomalies.iter().skip(scroll).take(visible).map(|a| {
        Row::new(vec![
            Cell::from(Span::styled(&a.ip, Style::default().fg(C_CYAN))),
            Cell::from(Span::styled(&a.old_mac, Style::default().fg(C_FG3))),
            Cell::from(Span::styled(&a.new_mac, Style::default().fg(C_RED))),
            Cell::from(Span::styled(a.pkt_no.to_string(), Style::default().fg(C_FG3))),
        ]).height(1)
    }).collect();

    let title = format!(" ARP Anomalies / MAC Changes ({}) ", anomalies.len());
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [Constraint::Length(18), Constraint::Length(20), Constraint::Length(20), Constraint::Min(0)],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, area);
    render_hint(f, area, "IP→MAC changes may indicate ARP spoofing / MITM attacks");
}

// ─── DNS Tunneling ────────────────────────────────────────────────────────────

fn draw_dns_tunnel(f: &mut Frame, app: &App, area: Rect) {
    let suspects = &app.security.dns_suspects;
    let scroll = app.security_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![
        cell_hdr("Apex Domain"), cell_hdr("Queries"), cell_hdr("Entropy"),
        cell_hdr("Max Label"), cell_hdr("Unique"), cell_hdr("Score"),
    ]).height(1);

    let rows: Vec<Row> = suspects.iter().skip(scroll).take(visible).map(|s| {
        let score_color = if s.score > 12.0 { C_RED }
            else if s.score > 8.0 { C_YELLOW }
            else { C_FG2 };
        Row::new(vec![
            Cell::from(Span::styled(&s.apex, Style::default().fg(C_CYAN))),
            Cell::from(Span::styled(s.query_count.to_string(), Style::default().fg(C_FG2))),
            Cell::from(Span::styled(format!("{:.2}", s.max_entropy), Style::default().fg(C_FG2))),
            Cell::from(Span::styled(s.max_subdomain_len.to_string(), Style::default().fg(C_FG2))),
            Cell::from(Span::styled(s.unique_subdomains.to_string(), Style::default().fg(C_FG2))),
            Cell::from(Span::styled(format!("{:.1}", s.score), Style::default().fg(score_color))),
        ]).height(1)
    }).collect();

    let title = format!(" DNS Tunnel Suspects ({}) ", suspects.len());
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [Constraint::Length(26), Constraint::Length(9), Constraint::Length(10),
         Constraint::Length(11), Constraint::Length(9), Constraint::Min(0)],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, area);
    render_hint(f, area, "High entropy subdomains may indicate DNS tunneling (e.g. iodine, dnscat2)");
}

// ─── HTTP Analytics ──────────────────────────────────────────────────────────

fn draw_http(f: &mut Frame, app: &App, area: Rect) {
    let records = &app.security.http_records;
    let scroll = app.security_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![
        cell_hdr("Method"), cell_hdr("Path"), cell_hdr("Code"), cell_hdr("Src"), cell_hdr("User-Agent"),
    ]).height(1);

    let rows: Vec<Row> = records.iter().skip(scroll).take(visible).map(|r| {
        let method_color = match r.method.as_str() {
            "GET"    => C_GREEN,
            "POST"   => C_YELLOW,
            "PUT"    => C_CYAN,
            "DELETE" => C_RED,
            _        => C_FG2,
        };
        let code_color = match r.response_code {
            Some(c) if c >= 500 => C_RED,
            Some(c) if c >= 400 => C_YELLOW,
            Some(c) if c >= 300 => C_CYAN,
            Some(c) if c >= 200 => C_GREEN,
            _ => C_FG3,
        };
        Row::new(vec![
            Cell::from(Span::styled(&r.method, Style::default().fg(method_color))),
            Cell::from(Span::styled(&r.path, Style::default().fg(C_FG))),
            Cell::from(Span::styled(
                r.response_code.map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
                Style::default().fg(code_color),
            )),
            Cell::from(Span::styled(&r.src_ip, Style::default().fg(C_FG3))),
            Cell::from(Span::styled(&r.user_agent, Style::default().fg(C_FG3))),
        ]).height(1)
    }).collect();

    let title = format!(" HTTP Requests ({}) ", records.len());
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [Constraint::Length(8), Constraint::Length(30), Constraint::Length(6),
         Constraint::Length(16), Constraint::Min(0)],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, area);
    render_hint(f, area, "HTTP traffic decoded from captured packets");
}

// ─── TLS Weakness ────────────────────────────────────────────────────────────

fn draw_tls(f: &mut Frame, app: &App, area: Rect) {
    let weaknesses = &app.security.tls_weaknesses;
    let scroll = app.security_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![
        cell_hdr("Issue"), cell_hdr("Src → Dst"), cell_hdr("Detail"), cell_hdr("Pkt#"),
    ]).height(1);

    let rows: Vec<Row> = weaknesses.iter().skip(scroll).take(visible).map(|w| {
        Row::new(vec![
            Cell::from(Span::styled(w.kind, Style::default().fg(C_YELLOW))),
            Cell::from(Span::styled(
                format!("{} → {}", w.src_ip, w.dst_ip),
                Style::default().fg(C_FG2),
            )),
            Cell::from(Span::styled(&w.detail, Style::default().fg(C_FG))),
            Cell::from(Span::styled(w.pkt_no.to_string(), Style::default().fg(C_FG3))),
        ]).height(1)
    }).collect();

    let title = format!(" TLS/SSL Weaknesses ({}) ", weaknesses.len());
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [Constraint::Length(22), Constraint::Length(34), Constraint::Min(0), Constraint::Length(7)],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, area);
    render_hint(f, area, "Outdated TLS versions, RC4 ciphers, SHA-1 certificates");
}

// ─── Brute Force ─────────────────────────────────────────────────────────────

fn draw_brute(f: &mut Frame, app: &App, area: Rect) {
    let alerts = &app.security.brute_force;
    let scroll = app.security_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![
        cell_hdr("Src IP"), cell_hdr("Dst IP"), cell_hdr("Port/Svc"), cell_hdr("Attempts"),
    ]).height(1);

    let rows: Vec<Row> = alerts.iter().skip(scroll).take(visible).map(|a| {
        Row::new(vec![
            Cell::from(Span::styled(&a.src_ip, Style::default().fg(C_RED))),
            Cell::from(Span::styled(&a.dst_ip, Style::default().fg(C_CYAN))),
            Cell::from(Span::styled(
                format!("{}/{}", a.port, a.service),
                Style::default().fg(C_YELLOW),
            )),
            Cell::from(Span::styled(a.attempts.to_string(), Style::default().fg(C_RED))),
        ]).height(1)
    }).collect();

    let title = format!(" Brute-Force Alerts ({}) ", alerts.len());
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [Constraint::Length(18), Constraint::Length(18), Constraint::Length(16), Constraint::Min(0)],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, area);
    render_hint(f, area, "Repeated auth failures from same source (SSH, FTP, HTTP, SMB)");
}

// ─── Vulnerability Hits ───────────────────────────────────────────────────────

fn draw_vuln(f: &mut Frame, app: &App, area: Rect) {
    let hits = &app.security.vuln_hits;
    let scroll = app.security_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![
        cell_hdr("Pkt#"), cell_hdr("Kind / CVE"), cell_hdr("Detail"),
    ]).height(1);

    let rows: Vec<Row> = hits.iter().skip(scroll).take(visible).map(|h| {
        Row::new(vec![
            Cell::from(Span::styled(h.pkt_no.to_string(), Style::default().fg(C_FG3))),
            Cell::from(Span::styled(h.kind, Style::default().fg(C_RED))),
            Cell::from(Span::styled(&h.detail, Style::default().fg(C_FG))),
        ]).height(1)
    }).collect();

    let title = format!(" Vulnerability Patterns ({}) ", hits.len());
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [Constraint::Length(7), Constraint::Length(28), Constraint::Min(0)],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, area);
    render_hint(f, area, "CVE patterns, weak protocols, cleartext sensitive paths");
}

// ─── PCAP Replay ─────────────────────────────────────────────────────────────

fn draw_replay(f: &mut Frame, app: &App, area: Rect) {
    let replay = &app.replay;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(0)])
        .split(area);

    let pct = replay.progress_pct();
    let bar_w = chunks[0].width.saturating_sub(22) as usize;
    let filled = (bar_w * pct as usize / 100).min(bar_w);
    let bar = format!("[{}{}] {}%",
        "█".repeat(filled), "░".repeat(bar_w - filled), pct);

    let status = if replay.complete { "✓ complete" }
        else if replay.running { "● playing" }
        else if replay.error.is_some() { "✗ error" }
        else { "idle" };

    let path_display = if app.replay_editing {
        format!("{}_", replay.path)
    } else if replay.path.is_empty() {
        "<no file — press e to edit>".into()
    } else {
        replay.path.clone()
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(" File:   ", Style::default().fg(C_FG2)),
            Span::styled(path_display, Style::default().fg(
                if app.replay_editing { C_YELLOW } else { C_CYAN }
            )),
        ]),
        Line::from(vec![
            Span::styled(" Speed:  ", Style::default().fg(C_FG2)),
            Span::styled(format!("{}x", replay.speed), Style::default().fg(C_YELLOW)),
            Span::styled("  [<] slower  [>] faster", Style::default().fg(C_FG3)),
        ]),
        Line::from(vec![
            Span::styled(" Status: ", Style::default().fg(C_FG2)),
            Span::styled(status, Style::default().fg(if replay.running { C_GREEN } else { C_FG3 })),
            Span::styled(format!("  {}/{} pkts  ", replay.current, replay.total), Style::default().fg(C_FG3)),
        ]),
        Line::from(vec![
            Span::styled(" ", Style::default()),
            Span::styled(&bar, Style::default().fg(C_CYAN)),
        ]),
    ];

    let err_str;
    let status_line = if let Some(e) = &replay.error {
        err_str = format!(" Error: {}", e);
        Span::styled(&err_str, Style::default().fg(C_RED))
    } else {
        Span::styled(
            " [e] edit path  [Enter] load  [Space] play/stop  [</>] speed  [C] clear",
            Style::default().fg(C_FG3),
        )
    };

    f.render_widget(
        Paragraph::new(lines)
            .block(block_titled(" PCAP Replay "))
            .style(Style::default().bg(C_BG)),
        chunks[0],
    );
    f.render_widget(
        Paragraph::new(Line::from(status_line))
            .style(Style::default().bg(C_BG2)),
        chunks[1],
    );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn cell_hdr(s: &str) -> Cell<'_> {
    Cell::from(Span::styled(s, Style::default().fg(C_FG3).add_modifier(Modifier::BOLD)))
}

fn block_titled(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(title.to_string(), Style::default().fg(C_FG2)))
}

fn render_hint(f: &mut Frame, area: Rect, hint: &str) {
    let hint_area = Rect {
        x: area.x + 1,
        y: area.y + area.height.saturating_sub(1),
        width: area.width.saturating_sub(2),
        height: 1,
    };
    f.render_widget(
        Paragraph::new(Span::styled(hint, Style::default().fg(C_FG3))),
        hint_area,
    );
}

// ─── IOC Hits ─────────────────────────────────────────────────────────────────

fn draw_ioc_hits(f: &mut Frame, app: &App, area: Rect) {
    let hits = &app.ioc_engine.hits;
    let scroll = app.security_scroll;

    let header = Row::new(vec![
        cell_hdr("Pkt#"), cell_hdr("Kind"), cell_hdr("IOC Value"), cell_hdr("Context"), cell_hdr("Description"),
    ]).height(1);

    let rows: Vec<Row> = hits.iter().skip(scroll)
        .take(area.height.saturating_sub(4) as usize)
        .map(|h| {
            let kind_style = Style::default().fg(match h.ioc.kind {
                crate::analysis::ioc::IocKind::Ip     => C_RED,
                crate::analysis::ioc::IocKind::Domain => C_ORANGE,
                crate::analysis::ioc::IocKind::Hash   => C_YELLOW,
                crate::analysis::ioc::IocKind::Url    => C_CYAN,
                crate::analysis::ioc::IocKind::Email  => C_FG2,
            }).add_modifier(Modifier::BOLD);
            Row::new(vec![
                Cell::from(format!("#{}", h.pkt_no)).style(Style::default().fg(C_FG3)),
                Cell::from(h.ioc.kind.to_string()).style(kind_style),
                Cell::from(h.ioc.value.clone()).style(Style::default().fg(C_RED)),
                Cell::from(h.context.clone()).style(Style::default().fg(C_CYAN)),
                Cell::from(h.ioc.description.clone()).style(Style::default().fg(C_FG2)),
            ])
        }).collect();

    let title = format!(" IOC Hits — {} hits  {} indicators loaded ", hits.len(), app.ioc_engine.ioc_count());
    let table = Table::new(rows, [
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(22),
        Constraint::Length(16),
        Constraint::Min(20),
    ])
    .header(header)
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, area);

    render_hint(f, area, "[j/k] scroll  [I] reload IOC feeds  [C] clear");
}
