use super::*;

pub(super) fn draw_vuln(f: &mut Frame, app: &App, area: Rect) {
    let hits = &app.security.vuln_hits;
    let scroll = app.security_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![
        cell_hdr("Pkt#"),
        cell_hdr("Kind / CVE"),
        cell_hdr("Detail"),
    ])
    .height(1);

    let rows: Vec<Row> = hits
        .iter()
        .skip(scroll)
        .take(visible)
        .map(|h| {
            Row::new(vec![
                Cell::from(Span::styled(
                    h.pkt_no.to_string(),
                    Style::default().fg(C_FG3()),
                )),
                Cell::from(Span::styled(h.kind, Style::default().fg(C_RED()))),
                Cell::from(Span::styled(&h.detail, Style::default().fg(C_FG()))),
            ])
            .height(1)
        })
        .collect();

    let title = format!(" Vulnerability Patterns ({}) ", hits.len());
    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [
            Constraint::Length(7),
            Constraint::Length(28),
            Constraint::Min(0),
        ],
    )
    .block(block_titled(&title))
    .style(Style::default().bg(C_BG()));
    f.render_widget(table, area);
    render_hint(
        f,
        area,
        "CVE patterns, weak protocols, cleartext sensitive paths",
    );
}
