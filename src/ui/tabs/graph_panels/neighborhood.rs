use super::*;

pub fn draw_neighborhood(f: &mut Frame, app: &App, area: Rect) {
    let engine = &app.core.operator_graph;
    let selected = app.graph_ui.selected_node;

    let mut lines: Vec<Line> = Vec::new();

    if let Some(node_id) = selected {
        if let Some(node) = engine.get_node(node_id) {
            // Root node
            lines.push(Line::from(vec![
                Span::styled(
                    format!("◉ [{}] ", node.kind().tag()),
                    node_kind_style(node.kind()).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    node.label.clone(),
                    Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("  {} {}", node.stars(), node.risk_label()),
                    Style::default().fg(score_color(node.score)),
                ),
            ]));
            lines.push(Line::raw(""));

            // Outgoing neighbors
            let out_eids = engine.out_edges(node_id);
            if !out_eids.is_empty() {
                lines.push(Line::from(Span::styled(
                    " ─ outgoing ─",
                    Style::default().fg(C_FG3()),
                )));
                let scroll = app.graph_ui.neighbor_scroll;
                let visible: Vec<_> = out_eids
                    .iter()
                    .skip(scroll)
                    .take((area.height.saturating_sub(8) / 2) as usize)
                    .filter_map(|&eid| {
                        let edge = engine.get_edge(eid)?;
                        let neighbor = engine.get_node(edge.dst)?;
                        Some((edge, neighbor))
                    })
                    .collect();

                for (edge, neighbor) in &visible {
                    lines.push(Line::from(vec![
                        Span::styled("  ├─", Style::default().fg(C_FG3())),
                        Span::styled(format!(" {} ", edge.kind), Style::default().fg(C_YELLOW())),
                        Span::styled("──► ", Style::default().fg(C_FG3())),
                        Span::styled(
                            format!("[{}] ", neighbor.kind().tag()),
                            node_kind_style(neighbor.kind()),
                        ),
                        Span::styled(truncate(&neighbor.label, 24), Style::default().fg(C_FG2())),
                        Span::styled(
                            format!(" #{}", edge.hit_count),
                            Style::default().fg(C_FG3()),
                        ),
                    ]));
                }

                if out_eids.len() > visible.len() {
                    lines.push(Line::from(Span::styled(
                        format!("  └─ +{} more…", out_eids.len() - visible.len()),
                        Style::default().fg(C_FG3()),
                    )));
                }
            }

            // Incoming neighbors
            let in_eids = engine.in_edges(node_id);
            if !in_eids.is_empty() {
                lines.push(Line::raw(""));
                lines.push(Line::from(Span::styled(
                    " ─ incoming ─",
                    Style::default().fg(C_FG3()),
                )));
                for &eid in in_eids.iter().take(8) {
                    if let (Some(edge), Some(neighbor)) = (
                        engine.get_edge(eid),
                        engine.get_node(engine.get_edge(eid).map(|e| e.src).unwrap_or(0)),
                    ) {
                        lines.push(Line::from(vec![
                            Span::styled("  ◄── ", Style::default().fg(C_FG3())),
                            Span::styled(
                                format!(" {} ", edge.kind),
                                Style::default().fg(C_YELLOW()),
                            ),
                            Span::styled(" ── ", Style::default().fg(C_FG3())),
                            Span::styled(
                                format!("[{}] ", neighbor.kind().tag()),
                                node_kind_style(neighbor.kind()),
                            ),
                            Span::styled(
                                truncate(&neighbor.label, 24),
                                Style::default().fg(C_FG2()),
                            ),
                        ]));
                    }
                }
            }
        }
    } else {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            "  Select a node from the list to explore relationships.",
            Style::default().fg(C_FG3()),
        )));
        if app.core.operator_graph.node_count() == 0 {
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled(
                "  Start capture or load a PCAP — the graph builds automatically.",
                Style::default().fg(C_FG3()),
            )));
        }
    }

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER()))
                .title(Span::styled(
                    " Neighborhood ",
                    Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
                )),
        )
        .style(Style::default().bg(C_BG()))
        .wrap(Wrap { trim: false });
    f.render_widget(panel, area);
}
