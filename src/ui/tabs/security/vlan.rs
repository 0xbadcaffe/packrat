use super::*;

// ─── VLAN Intelligence ───────────────────────────────────────────────────────

pub(super) fn draw_vlan_intel(f: &mut Frame, app: &App, area: Rect) {
    use crate::analysis::vlan::AlertSeverity;

    let intel = &app.vlan_intel;
    let scroll = app.security_scroll;

    // Split area: top half stats table, bottom half alert table
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    // ── Per-VLAN stats ───────────────────────────────────────────────────────
    let stats_header = Row::new(vec![
        cell_hdr("VLAN ID"),
        cell_hdr("Packets"),
        cell_hdr("Bytes"),
        cell_hdr("Hosts"),
        cell_hdr("First Seen"),
        cell_hdr("Last Seen"),
    ])
    .height(1);

    let stats_rows: Vec<Row> = intel
        .stats
        .values()
        .skip(scroll)
        .take(chunks[0].height.saturating_sub(4) as usize)
        .map(|s| {
            let vlan_color = if s.vlan_id == 1 { C_RED() } else { C_CYAN() };
            Row::new(vec![
                Cell::from(Span::styled(
                    s.vlan_id.to_string(),
                    Style::default().fg(vlan_color).add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(
                    s.packets.to_string(),
                    Style::default().fg(C_FG()),
                )),
                Cell::from(Span::styled(
                    format_bytes(s.bytes),
                    Style::default().fg(C_GREEN()),
                )),
                Cell::from(Span::styled(
                    s.hosts.len().to_string(),
                    Style::default().fg(C_YELLOW()),
                )),
                Cell::from(Span::styled(
                    fmt_ts(s.first_seen),
                    Style::default().fg(C_FG3()),
                )),
                Cell::from(Span::styled(
                    fmt_ts(s.last_seen),
                    Style::default().fg(C_FG3()),
                )),
            ])
        })
        .collect();

    let stats_title = format!(
        " VLAN Stats — {} VLAN{} observed ",
        intel.vlan_count(),
        if intel.vlan_count() == 1 { "" } else { "s" }
    );
    let stats_table = Table::new(
        std::iter::once(stats_header)
            .chain(stats_rows)
            .collect::<Vec<_>>(),
        [
            Constraint::Length(9),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(8),
            Constraint::Length(14),
            Constraint::Length(14),
        ],
    )
    .block(block_titled(&stats_title))
    .style(Style::default().bg(C_BG()));
    f.render_widget(stats_table, chunks[0]);

    // ── VLAN Alerts ──────────────────────────────────────────────────────────
    let alerts = intel.alerts_newest_first();
    let alert_header = Row::new(vec![
        cell_hdr("Pkt#"),
        cell_hdr("Sev"),
        cell_hdr("Category"),
        cell_hdr("Detail"),
    ])
    .height(1);

    let alert_rows: Vec<Row> = alerts
        .iter()
        .take(chunks[1].height.saturating_sub(4) as usize)
        .map(|a| {
            let sev_color = match a.severity {
                AlertSeverity::Critical => C_RED(),
                AlertSeverity::Warning => C_YELLOW(),
                AlertSeverity::Info => C_FG2(),
            };
            let cat_color = match a.category.as_str() {
                "VLAN-Hop" | "DTP" => C_RED(),
                "MAC-VLAN-Cross" => C_ORANGE(),
                "PCP-Abuse" => C_YELLOW(),
                "Native-VLAN" => C_CYAN(),
                _ => C_FG2(),
            };
            Row::new(vec![
                Cell::from(Span::styled(
                    format!("#{}", a.pkt_no),
                    Style::default().fg(C_FG3()),
                )),
                Cell::from(Span::styled(
                    a.severity.to_string(),
                    Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(&a.category, Style::default().fg(cat_color))),
                Cell::from(Span::styled(&a.detail, Style::default().fg(C_FG()))),
            ])
        })
        .collect();

    let alert_title = format!(
        " VLAN Alerts — {} total ({} critical) ",
        alerts.len(),
        intel.critical_alerts().len()
    );
    let alert_table = Table::new(
        std::iter::once(alert_header)
            .chain(alert_rows)
            .collect::<Vec<_>>(),
        [
            Constraint::Length(9),
            Constraint::Length(6),
            Constraint::Length(16),
            Constraint::Min(0),
        ],
    )
    .block(block_titled(&alert_title))
    .style(Style::default().bg(C_BG()));
    f.render_widget(alert_table, chunks[1]);

    render_hint(
        f,
        area,
        "[/] detector view  [j/k] scroll  [C] clear  Detects: double-tag, DTP, MAC-cross-VLAN, PCP-abuse, native-VLAN-1",
    );
}
