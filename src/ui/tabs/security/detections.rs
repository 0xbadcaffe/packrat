use super::*;

// ─── IDS Alerts ──────────────────────────────────────────────────────────────

pub(super) fn draw_ids(f: &mut Frame, app: &App, area: Rect) {
    let alerts = &app.security.ids_alerts;
    let scroll = app.security_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![
        cell_hdr("Pkt#"),
        cell_hdr("Severity"),
        cell_hdr("Signature"),
        cell_hdr("Detail"),
    ])
    .height(1);

    let rows: Vec<Row> = alerts
        .iter()
        .skip(scroll)
        .take(visible)
        .map(|a| {
            let sev_color = match a.severity {
                Severity::Critical => C_RED(),
                Severity::High => Color::Rgb(215, 135, 0),
                Severity::Medium => C_YELLOW(),
                Severity::Low => C_GREEN(),
            };
            Row::new(vec![
                Cell::from(Span::styled(
                    a.pkt_no.to_string(),
                    Style::default().fg(C_FG3()),
                )),
                Cell::from(Span::styled(
                    a.severity.to_string(),
                    Style::default().fg(sev_color),
                )),
                Cell::from(Span::styled(a.signature, Style::default().fg(C_CYAN()))),
                Cell::from(Span::styled(&a.detail, Style::default().fg(C_FG()))),
            ])
            .height(1)
        })
        .collect();

    let count_str = format!(" IDS Alerts ({}) ", alerts.len());
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [
            Constraint::Length(7),
            Constraint::Length(10),
            Constraint::Length(28),
            Constraint::Min(0),
        ],
    )
    .block(block_titled(&count_str))
    .style(Style::default().bg(C_BG()));
    f.render_widget(table, area);
    render_hint(
        f,
        area,
        "[/] detector view  [j/k] scroll  [C] clear  [q] quit",
    );
}

// ─── Credentials ─────────────────────────────────────────────────────────────

pub(super) fn draw_creds(f: &mut Frame, app: &App, area: Rect) {
    let creds = &app.credentials;
    let scroll = app.security_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![cell_hdr("Pkt#"), cell_hdr("Type"), cell_hdr("Value")]).height(1);

    let rows: Vec<Row> = creds
        .iter()
        .skip(scroll)
        .take(visible)
        .map(|c| {
            Row::new(vec![
                Cell::from(Span::styled(
                    c.pkt_no.to_string(),
                    Style::default().fg(C_FG3()),
                )),
                Cell::from(Span::styled(c.kind, Style::default().fg(C_YELLOW()))),
                Cell::from(Span::styled(&c.value, Style::default().fg(C_RED()))),
            ])
            .height(1)
        })
        .collect();

    let title = format!(" Cleartext Credentials ({}) ", creds.len());
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [
            Constraint::Length(7),
            Constraint::Length(18),
            Constraint::Min(0),
        ],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG()));
    f.render_widget(table, area);
    render_hint(
        f,
        area,
        "Cleartext credentials detected in captured traffic",
    );
}

// ─── OS Fingerprint ──────────────────────────────────────────────────────────

pub(super) fn draw_os(f: &mut Frame, app: &App, area: Rect) {
    let guesses = &app.security.os_guesses;
    let scroll = app.security_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![
        cell_hdr("IP Address"),
        cell_hdr("OS Guess"),
        cell_hdr("TTL"),
        cell_hdr("Window"),
    ])
    .height(1);

    let rows: Vec<Row> = guesses
        .iter()
        .skip(scroll)
        .take(visible)
        .map(|g| {
            Row::new(vec![
                Cell::from(Span::styled(&g.src_ip, Style::default().fg(C_CYAN()))),
                Cell::from(Span::styled(g.os, Style::default().fg(C_FG()))),
                Cell::from(Span::styled(
                    g.ttl.to_string(),
                    Style::default().fg(C_FG2()),
                )),
                Cell::from(Span::styled(
                    g.window.to_string(),
                    Style::default().fg(C_FG2()),
                )),
            ])
            .height(1)
        })
        .collect();

    let title = format!(" OS Fingerprints ({} hosts) ", guesses.len());
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [
            Constraint::Length(18),
            Constraint::Length(30),
            Constraint::Length(6),
            Constraint::Min(0),
        ],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG()));
    f.render_widget(table, area);
    render_hint(f, area, "Passive OS detection from TTL and TCP window size");
}

// ─── ARP Watch ───────────────────────────────────────────────────────────────

pub(super) fn draw_arp(f: &mut Frame, app: &App, area: Rect) {
    let anomalies = &app.security.arp_anomalies;
    let scroll = app.security_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![
        cell_hdr("IP"),
        cell_hdr("Old MAC"),
        cell_hdr("New MAC"),
        cell_hdr("Pkt#"),
    ])
    .height(1);

    let rows: Vec<Row> = anomalies
        .iter()
        .skip(scroll)
        .take(visible)
        .map(|a| {
            Row::new(vec![
                Cell::from(Span::styled(&a.ip, Style::default().fg(C_CYAN()))),
                Cell::from(Span::styled(&a.old_mac, Style::default().fg(C_FG3()))),
                Cell::from(Span::styled(&a.new_mac, Style::default().fg(C_RED()))),
                Cell::from(Span::styled(
                    a.pkt_no.to_string(),
                    Style::default().fg(C_FG3()),
                )),
            ])
            .height(1)
        })
        .collect();

    let title = format!(" ARP Anomalies / MAC Changes ({}) ", anomalies.len());
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [
            Constraint::Length(18),
            Constraint::Length(20),
            Constraint::Length(20),
            Constraint::Min(0),
        ],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG()));
    f.render_widget(table, area);
    render_hint(
        f,
        area,
        "IP→MAC changes may indicate ARP spoofing / MITM attacks",
    );
}

// ─── DNS Tunneling ────────────────────────────────────────────────────────────

pub(super) fn draw_dns_tunnel(f: &mut Frame, app: &App, area: Rect) {
    let suspects = &app.security.dns_suspects;
    let scroll = app.security_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![
        cell_hdr("Apex Domain"),
        cell_hdr("Queries"),
        cell_hdr("Entropy"),
        cell_hdr("Max Label"),
        cell_hdr("Unique"),
        cell_hdr("Score"),
    ])
    .height(1);

    let rows: Vec<Row> = suspects
        .iter()
        .skip(scroll)
        .take(visible)
        .map(|s| {
            let score_color = if s.score > 12.0 {
                C_RED()
            } else if s.score > 8.0 {
                C_YELLOW()
            } else {
                C_FG2()
            };
            Row::new(vec![
                Cell::from(Span::styled(&s.apex, Style::default().fg(C_CYAN()))),
                Cell::from(Span::styled(
                    s.query_count.to_string(),
                    Style::default().fg(C_FG2()),
                )),
                Cell::from(Span::styled(
                    format!("{:.2}", s.max_entropy),
                    Style::default().fg(C_FG2()),
                )),
                Cell::from(Span::styled(
                    s.max_subdomain_len.to_string(),
                    Style::default().fg(C_FG2()),
                )),
                Cell::from(Span::styled(
                    s.unique_subdomains.to_string(),
                    Style::default().fg(C_FG2()),
                )),
                Cell::from(Span::styled(
                    format!("{:.1}", s.score),
                    Style::default().fg(score_color),
                )),
            ])
            .height(1)
        })
        .collect();

    let title = format!(" DNS Tunnel Suspects ({}) ", suspects.len());
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [
            Constraint::Length(26),
            Constraint::Length(9),
            Constraint::Length(10),
            Constraint::Length(11),
            Constraint::Length(9),
            Constraint::Min(0),
        ],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG()));
    f.render_widget(table, area);
    render_hint(
        f,
        area,
        "High entropy subdomains may indicate DNS tunneling (e.g. iodine, dnscat2)",
    );
}

// ─── HTTP Analytics ──────────────────────────────────────────────────────────

pub(super) fn draw_http(f: &mut Frame, app: &App, area: Rect) {
    let records = &app.security.http_records;
    let scroll = app.security_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![
        cell_hdr("Method"),
        cell_hdr("Path"),
        cell_hdr("Code"),
        cell_hdr("Src"),
        cell_hdr("User-Agent"),
    ])
    .height(1);

    let rows: Vec<Row> = records
        .iter()
        .skip(scroll)
        .take(visible)
        .map(|r| {
            let method_color = match r.method.as_str() {
                "GET" => C_GREEN(),
                "POST" => C_YELLOW(),
                "PUT" => C_CYAN(),
                "DELETE" => C_RED(),
                _ => C_FG2(),
            };
            let code_color = match r.response_code {
                Some(c) if c >= 500 => C_RED(),
                Some(c) if c >= 400 => C_YELLOW(),
                Some(c) if c >= 300 => C_CYAN(),
                Some(c) if c >= 200 => C_GREEN(),
                _ => C_FG3(),
            };
            Row::new(vec![
                Cell::from(Span::styled(&r.method, Style::default().fg(method_color))),
                Cell::from(Span::styled(&r.path, Style::default().fg(C_FG()))),
                Cell::from(Span::styled(
                    r.response_code
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "-".into()),
                    Style::default().fg(code_color),
                )),
                Cell::from(Span::styled(&r.src_ip, Style::default().fg(C_FG3()))),
                Cell::from(Span::styled(&r.user_agent, Style::default().fg(C_FG3()))),
            ])
            .height(1)
        })
        .collect();

    let title = format!(" HTTP Requests ({}) ", records.len());
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [
            Constraint::Length(8),
            Constraint::Length(30),
            Constraint::Length(6),
            Constraint::Length(16),
            Constraint::Min(0),
        ],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG()));
    f.render_widget(table, area);
    render_hint(f, area, "HTTP traffic decoded from captured packets");
}

// ─── TLS Weakness ────────────────────────────────────────────────────────────

pub(super) fn draw_tls(f: &mut Frame, app: &App, area: Rect) {
    let weaknesses = &app.security.tls_weaknesses;
    let scroll = app.security_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![
        cell_hdr("Issue"),
        cell_hdr("Src → Dst"),
        cell_hdr("Detail"),
        cell_hdr("Pkt#"),
    ])
    .height(1);

    let rows: Vec<Row> = weaknesses
        .iter()
        .skip(scroll)
        .take(visible)
        .map(|w| {
            Row::new(vec![
                Cell::from(Span::styled(w.kind, Style::default().fg(C_YELLOW()))),
                Cell::from(Span::styled(
                    format!("{} → {}", w.src_ip, w.dst_ip),
                    Style::default().fg(C_FG2()),
                )),
                Cell::from(Span::styled(&w.detail, Style::default().fg(C_FG()))),
                Cell::from(Span::styled(
                    w.pkt_no.to_string(),
                    Style::default().fg(C_FG3()),
                )),
            ])
            .height(1)
        })
        .collect();

    let title = format!(" TLS/SSL Weaknesses ({}) ", weaknesses.len());
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [
            Constraint::Length(22),
            Constraint::Length(34),
            Constraint::Min(0),
            Constraint::Length(7),
        ],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG()));
    f.render_widget(table, area);
    render_hint(
        f,
        area,
        "Outdated TLS versions, RC4 ciphers, SHA-1 certificates",
    );
}

// ─── Brute Force ─────────────────────────────────────────────────────────────

pub(super) fn draw_brute(f: &mut Frame, app: &App, area: Rect) {
    let alerts = &app.security.brute_force;
    let scroll = app.security_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![
        cell_hdr("Src IP"),
        cell_hdr("Dst IP"),
        cell_hdr("Port/Svc"),
        cell_hdr("Attempts"),
    ])
    .height(1);

    let rows: Vec<Row> = alerts
        .iter()
        .skip(scroll)
        .take(visible)
        .map(|a| {
            Row::new(vec![
                Cell::from(Span::styled(&a.src_ip, Style::default().fg(C_RED()))),
                Cell::from(Span::styled(&a.dst_ip, Style::default().fg(C_CYAN()))),
                Cell::from(Span::styled(
                    format!("{}/{}", a.port, a.service),
                    Style::default().fg(C_YELLOW()),
                )),
                Cell::from(Span::styled(
                    a.attempts.to_string(),
                    Style::default().fg(C_RED()),
                )),
            ])
            .height(1)
        })
        .collect();

    let title = format!(" Brute-Force Alerts ({}) ", alerts.len());
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [
            Constraint::Length(18),
            Constraint::Length(18),
            Constraint::Length(16),
            Constraint::Min(0),
        ],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG()));
    f.render_widget(table, area);
    render_hint(
        f,
        area,
        "Repeated auth failures from same source (SSH, FTP, HTTP, SMB)",
    );
}

// ─── Vulnerability Hits ───────────────────────────────────────────────────────
