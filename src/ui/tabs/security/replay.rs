use super::*;

// ─── PCAP Replay ─────────────────────────────────────────────────────────────

pub(super) fn draw_replay(f: &mut Frame, app: &App, area: Rect) {
    let replay = &app.replay;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(0)])
        .split(area);

    let pct = replay.progress_pct();
    let bar_w = chunks[0].width.saturating_sub(22) as usize;
    let filled = (bar_w * pct as usize / 100).min(bar_w);
    let bar = format!(
        "[{}{}] {}%",
        "█".repeat(filled),
        "░".repeat(bar_w - filled),
        pct
    );

    let status = if replay.complete {
        "✓ complete"
    } else if replay.running {
        "● playing"
    } else if replay.error.is_some() {
        "✗ error"
    } else {
        "idle"
    };

    let path_display = if app.replay_editing {
        format!("{}_", replay.path)
    } else if replay.path.is_empty() {
        "<no file — press e to edit>".into()
    } else {
        replay.path.clone()
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(" File:   ", Style::default().fg(C_FG2())),
            Span::styled(
                path_display,
                Style::default().fg(if app.replay_editing {
                    C_YELLOW()
                } else {
                    C_CYAN()
                }),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Speed:  ", Style::default().fg(C_FG2())),
            Span::styled(
                format!("{}x", replay.speed),
                Style::default().fg(C_YELLOW()),
            ),
            Span::styled("  [<] slower  [>] faster", Style::default().fg(C_FG3())),
        ]),
        Line::from(vec![
            Span::styled(" Status: ", Style::default().fg(C_FG2())),
            Span::styled(
                status,
                Style::default().fg(if replay.running { C_GREEN() } else { C_FG3() }),
            ),
            Span::styled(
                format!("  {}/{} pkts  ", replay.current, replay.total),
                Style::default().fg(C_FG3()),
            ),
        ]),
        Line::from(vec![
            Span::styled(" ", Style::default()),
            Span::styled(&bar, Style::default().fg(C_CYAN())),
        ]),
    ];

    let err_str;
    let status_line = if let Some(e) = &replay.error {
        err_str = format!(" Error: {}", e);
        Span::styled(&err_str, Style::default().fg(C_RED()))
    } else {
        Span::styled(
            " [e] edit path  [Enter] load  [Space] play/stop  [</>] speed  [C] clear",
            Style::default().fg(C_FG3()),
        )
    };

    f.render_widget(
        Paragraph::new(lines)
            .block(block_titled(" PCAP Replay "))
            .style(Style::default().bg(C_BG())),
        chunks[0],
    );
    f.render_widget(
        Paragraph::new(Line::from(status_line)).style(Style::default().bg(C_BG2())),
        chunks[1],
    );
}
