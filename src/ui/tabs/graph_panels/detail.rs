use super::*;

// ─── Detail panel (right) ─────────────────────────────────────────────────────

pub fn draw_detail_panel(f: &mut Frame, app: &App, area: Rect) {
    let engine = &app.operator_graph;
    let mut lines: Vec<Line> = Vec::new();

    if let Some(node_id) = app.graph_ui.selected_node {
        if let Some(node) = engine.get_node(node_id) {
            let kind = node.kind();

            lines.push(Line::from(vec![
                Span::styled(
                    format!("[{}]", kind.tag()),
                    node_kind_style(kind.clone()).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!(" {}", kind), Style::default().fg(C_FG3())),
            ]));
            lines.push(Line::raw(""));

            lines.push(Line::from(vec![
                Span::styled("Label:  ", Style::default().fg(C_FG3())),
                Span::styled(
                    node.label.clone(),
                    Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD),
                ),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Risk:   ", Style::default().fg(C_FG3())),
                Span::styled(
                    format!("{:.2}  {} {}", node.score, node.stars(), node.risk_label()),
                    Style::default()
                        .fg(score_color(node.score))
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::raw(""));

            // Why
            if !node.score_why.is_empty() {
                lines.push(Line::from(Span::styled(
                    "Why:",
                    Style::default().fg(C_FG3()),
                )));
                for chunk in wrap_text(&node.score_why, area.width.saturating_sub(4) as usize) {
                    lines.push(Line::from(Span::styled(
                        format!("  {chunk}"),
                        Style::default().fg(C_FG2()),
                    )));
                }
                lines.push(Line::raw(""));
            }

            // Timestamps
            lines.push(Line::from(vec![
                Span::styled("First:  ", Style::default().fg(C_FG3())),
                Span::styled(format_ts(node.first_seen), Style::default().fg(C_FG2())),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Last:   ", Style::default().fg(C_FG3())),
                Span::styled(format_ts(node.last_seen), Style::default().fg(C_FG2())),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Hits:   ", Style::default().fg(C_FG3())),
                Span::styled(node.hit_count.to_string(), Style::default().fg(C_FG2())),
            ]));
            lines.push(Line::raw(""));

            // Tags
            if !node.tags.is_empty() {
                let tags: Vec<String> = node.tags.iter().cloned().collect();
                lines.push(Line::from(vec![
                    Span::styled("Tags:   ", Style::default().fg(C_FG3())),
                    Span::styled(tags.join(", "), Style::default().fg(C_YELLOW())),
                ]));
                lines.push(Line::raw(""));
            }

            // Connectivity
            let out_n = engine.out_edges(node_id).len();
            let in_n = engine.in_edges(node_id).len();
            lines.push(Line::from(vec![
                Span::styled("Degree: ", Style::default().fg(C_FG3())),
                Span::styled(format!("→{out_n} ←{in_n}"), Style::default().fg(C_FG2())),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Evid:   ", Style::default().fg(C_FG3())),
                Span::styled(
                    format!("{} refs", node.evidence.len()),
                    Style::default().fg(C_FG2()),
                ),
            ]));

            // Kind-specific payload summary
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled(
                "─ payload ─",
                Style::default().fg(C_FG3()),
            )));
            for kv in node_payload_summary(&node.data) {
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:8}", kv.0), Style::default().fg(C_FG3())),
                    Span::styled(
                        truncate(&kv.1, area.width.saturating_sub(12) as usize),
                        Style::default().fg(C_FG2()),
                    ),
                ]));
            }
        }
    } else {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            "  Select a node to view details.",
            Style::default().fg(C_FG3()),
        )));
    }

    let detail_scroll = app.graph_ui.detail_scroll;
    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER()))
                .title(Span::styled(
                    " Detail ",
                    Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
                )),
        )
        .style(Style::default().bg(C_BG()))
        .scroll((detail_scroll as u16, 0))
        .wrap(Wrap { trim: false });
    f.render_widget(panel, area);
}

pub(super) fn node_payload_summary(
    data: &crate::model::graph_types::GraphNodeData,
) -> Vec<(&'static str, String)> {
    use crate::model::graph_types::GraphNodeData;
    match data {
        GraphNodeData::Host(d) => vec![
            ("IPs", d.ips.join(", ")),
            (
                "Ports",
                d.open_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            ("Bytes↑", format!("{}", d.bytes_out)),
            ("Bytes↓", format!("{}", d.bytes_in)),
        ],
        GraphNodeData::Service(d) => vec![
            ("Port", format!("{}/{}", d.port, d.protocol)),
            ("Role", d.role.clone().unwrap_or("-".into())),
        ],
        GraphNodeData::Flow(d) => vec![
            ("Src", d.src.clone()),
            ("Dst", d.dst.clone()),
            ("Pkts", d.pkt_count.to_string()),
            ("Bytes", d.bytes.to_string()),
        ],
        GraphNodeData::Credential(d) => vec![
            ("Type", d.cred_type.clone()),
            ("User", d.username.clone().unwrap_or("-".into())),
            ("Clear", d.cleartext.to_string()),
        ],
        GraphNodeData::Certificate(d) => vec![
            ("Subj", d.subject.clone()),
            ("Self?", d.self_signed.to_string()),
            (
                "FP",
                d.fingerprint[..d.fingerprint.len().min(12)].to_string(),
            ),
        ],
        GraphNodeData::IOC(d) => vec![
            ("Kind", d.ioc_kind.clone()),
            ("Value", d.value.clone()),
            ("Src", d.source.clone()),
        ],
        GraphNodeData::Alert(d) => vec![
            ("Sig", d.signature.clone()),
            ("Sev", d.severity.clone()),
            ("Pkt", d.pkt_no.to_string()),
        ],
        GraphNodeData::FileObject(d) => vec![
            ("MIME", d.mime.clone()),
            ("Size", d.size.to_string()),
            ("SHA", d.sha256[..d.sha256.len().min(12)].to_string()),
        ],
        GraphNodeData::RuleHit(d) => vec![
            ("Rule", d.rule_name.clone()),
            ("Pkt", d.pkt_no.to_string()),
            ("Act", d.action.clone()),
        ],
        _ => vec![],
    }
}
