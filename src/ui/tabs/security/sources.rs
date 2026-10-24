use super::*;

pub(super) fn draw_process_scope(f: &mut Frame, app: &App, area: Rect) {
    let visible = area.height.saturating_sub(3) as usize;
    let header = Row::new(vec![
        cell_hdr("PID"),
        cell_hdr("UID"),
        cell_hdr("Process"),
        cell_hdr("Packets Out/In"),
        cell_hdr("Bytes Out"),
        cell_hdr("Bytes In"),
        cell_hdr("Last Seen"),
    ])
    .height(1);
    let rows = app
        .socket_scope
        .sorted_traffic()
        .into_iter()
        .skip(app.security_scroll)
        .take(visible)
        .map(|usage| {
            Row::new(vec![
                Cell::from(Span::styled(
                    usage.pid.to_string(),
                    Style::default().fg(C_CYAN()),
                )),
                Cell::from(Span::styled(
                    usage.uid.to_string(),
                    Style::default().fg(C_FG3()),
                )),
                Cell::from(Span::styled(
                    &usage.process,
                    Style::default().fg(C_YELLOW()),
                )),
                Cell::from(format!("{} / {}", usage.packets_out, usage.packets_in)),
                Cell::from(crate::ui::fmt_bytes(usage.bytes_out)),
                Cell::from(crate::ui::fmt_bytes(usage.bytes_in)),
                Cell::from(format!("{:.3}", usage.last_seen)),
            ])
        })
        .collect::<Vec<_>>();
    let title = format!(
        " SocketScope - {} attributed, {} imported, {} processes, {} eBPF lost ",
        app.socket_scope.owners.len(),
        app.socket_scope.imported_events,
        app.socket_scope.traffic.len(),
        app.socket_scope.ebpf_lost_events,
    );
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(22),
            Constraint::Length(16),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Min(0),
        ],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG()));
    f.render_widget(table, area);
    render_hint(
        f,
        area,
        "Linux /proc plus incremental eBPF/CSV attribution  [j/k] scroll  [/] views",
    );
}

pub(super) fn draw_route_policy(f: &mut Frame, app: &App, area: Rect) {
    let visible = area.height.saturating_sub(3) as usize;
    let header = Row::new(vec![
        cell_hdr("Pkt"),
        cell_hdr("Subject"),
        cell_hdr("Target"),
        cell_hdr("Port"),
        cell_hdr("Protocol"),
        cell_hdr("Authority"),
    ])
    .height(1);
    let rows = app
        .route_ledger
        .drift
        .iter()
        .rev()
        .skip(app.security_scroll)
        .take(visible)
        .map(|finding| {
            Row::new(vec![
                Cell::from(Span::styled(
                    finding.packet_no.to_string(),
                    Style::default().fg(C_FG3()),
                )),
                Cell::from(Span::styled(
                    &finding.route.subject,
                    Style::default().fg(C_YELLOW()),
                )),
                Cell::from(Span::styled(
                    &finding.route.target,
                    Style::default().fg(C_RED()),
                )),
                Cell::from(finding.route.port.to_string()),
                Cell::from(finding.route.protocol.as_str()),
                Cell::from(finding.route.authority.as_deref().unwrap_or("-")),
            ])
        })
        .collect::<Vec<_>>();
    let title = format!(
        " RouteLedger - mode: {}  baseline: {}  observed: {}  drift: {} ",
        app.route_ledger.mode,
        app.route_ledger.baseline.len(),
        app.route_ledger.observed.len(),
        app.route_ledger.drift.len(),
    );
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [
            Constraint::Length(8),
            Constraint::Length(22),
            Constraint::Length(20),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Min(0),
        ],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG()));
    f.render_widget(table, area);
    render_hint(
        f,
        area,
        "[l] observe -> learn -> drift detection  [y] promote observed routes  [j/k] scroll",
    );
}

pub(super) fn draw_wire_pulse(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Min(0)])
        .split(area);
    let histogram = app.wire_pulse.histogram();
    let labels = ["<1ms", "1-10", "10-50", "50-100", "100-250", ">=250"];
    let max = histogram.iter().copied().max().unwrap_or(1).max(1);
    let lines = labels
        .iter()
        .zip(histogram)
        .map(|(label, count)| {
            Line::from(vec![
                Span::styled(format!(" {label:<9}"), Style::default().fg(C_FG2())),
                Span::styled(
                    "█".repeat(count * 30 / max),
                    Style::default().fg(if label == &">=250" { C_RED() } else { C_CYAN() }),
                ),
                Span::styled(format!(" {count}"), Style::default().fg(C_FG3())),
            ])
        })
        .collect::<Vec<_>>();
    let summary = format!(
        " WirePulse - gateway: {}  median: {}  p95: {} ",
        app.wire_pulse.gateway.as_deref().unwrap_or("unknown"),
        app.wire_pulse
            .median_ms()
            .map(|value| format!("{value:.1}ms"))
            .unwrap_or_else(|| "-".into()),
        app.wire_pulse
            .p95_ms()
            .map(|value| format!("{value:.1}ms"))
            .unwrap_or_else(|| "-".into()),
    );
    f.render_widget(
        Paragraph::new(lines)
            .block(block_titled(&summary))
            .style(Style::default().bg(C_BG())),
        chunks[0],
    );

    let header = Row::new(vec![
        cell_hdr("Pkt"),
        cell_hdr("Kind"),
        cell_hdr("Target"),
        cell_hdr("Latency"),
        cell_hdr("Time"),
    ]);
    let rows = app
        .wire_pulse
        .samples
        .iter()
        .rev()
        .skip(app.security_scroll)
        .take(chunks[1].height.saturating_sub(3) as usize)
        .map(|sample| {
            Row::new(vec![
                Cell::from(sample.packet_no.to_string()),
                Cell::from(sample.kind.to_string()),
                Cell::from(sample.target.as_str()),
                Cell::from(format!("{:.2}ms", sample.latency_ms)),
                Cell::from(format!("{:.3}", sample.timestamp)),
            ])
        })
        .collect::<Vec<_>>();
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Length(24),
            Constraint::Length(14),
            Constraint::Min(0),
        ],
    )
    .block(block_titled(" Passive DNS and TCP Latency "))
    .style(Style::default().bg(C_BG()));
    f.render_widget(table, chunks[1]);
}

pub(super) fn draw_net_registry(f: &mut Frame, app: &App, area: Rect) {
    let entries = app.net_registry.sorted();
    let visible = area.height.saturating_sub(3) as usize;
    let header = Row::new(vec![
        cell_hdr("Address"),
        cell_hdr("ASN"),
        cell_hdr("Organization"),
        cell_hdr("Reputation"),
        cell_hdr("Severity"),
        cell_hdr("Source"),
    ]);
    let rows = entries
        .iter()
        .skip(app.security_scroll)
        .take(visible)
        .map(|identity| {
            Row::new(vec![
                Cell::from(identity.address.to_string()).style(Style::default().fg(C_CYAN())),
                Cell::from(identity.asn.as_deref().unwrap_or("-")),
                Cell::from(identity.organization.as_str()),
                Cell::from(
                    identity
                        .reputation
                        .as_ref()
                        .map(|finding| finding.label.as_str())
                        .unwrap_or("-"),
                )
                .style(Style::default().fg(if identity.reputation.is_some() {
                    C_RED()
                } else {
                    C_FG3()
                })),
                Cell::from(
                    identity
                        .reputation
                        .as_ref()
                        .map(|finding| finding.severity.as_str())
                        .unwrap_or("-"),
                )
                .style(Style::default().fg(if identity.reputation.is_some() {
                    C_ORANGE()
                } else {
                    C_FG3()
                })),
                Cell::from(identity.source.as_str()).style(Style::default().fg(C_FG3())),
            ])
        })
        .collect::<Vec<_>>();
    let title = format!(
        " NetRegistry - {} observed addresses, {} prefixes, {} reputation entries ",
        entries.len(),
        app.net_registry.prefixes.len(),
        app.net_registry.reputation.len(),
    );
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [
            Constraint::Length(22),
            Constraint::Length(12),
            Constraint::Length(26),
            Constraint::Length(20),
            Constraint::Length(10),
            Constraint::Min(14),
        ],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG()));
    f.render_widget(table, area);
    render_hint(
        f,
        area,
        "Maps: identity-map.csv + reputation-map.csv  [r] explicit WHOIS refresh  [j/k] select",
    );
}
