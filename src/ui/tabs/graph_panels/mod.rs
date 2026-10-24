//! Graph panel renderers — node list, neighborhood, adjacency, detail, etc.

use crate::app::AppView as App;
use crate::model::graph_types::GraphNodeKind;
use crate::ui::theme::*;
use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, Wrap},
};

// ─── Node list (left panel) ───────────────────────────────────────────────────

pub fn draw_node_list(f: &mut Frame, app: &App, area: Rect) {
    let engine = &app.core.operator_graph;
    let filter = &app.graph_ui.filter;
    let snap = engine.filtered_snapshot(filter);

    let scroll = app.graph_ui.list_scroll;
    let selected = app.graph_ui.selected_node;

    let items: Vec<ListItem> = snap
        .node_ids
        .iter()
        .skip(scroll)
        .take(area.height.saturating_sub(2) as usize)
        .filter_map(|&id| engine.get_node(id))
        .map(|node| {
            let is_sel = selected == Some(node.id);
            let score_bar = score_to_bar(node.score);
            let kind_tag = node.kind().tag();
            let label_max = 18.max(area.width.saturating_sub(14) as usize);
            let label = truncate(&node.label, label_max);

            let node_style = node_kind_style(node.kind());
            let bg = if is_sel {
                Style::default().bg(C_SEL_BG()).fg(C_FG())
            } else {
                Style::default()
            };

            ListItem::new(Line::from(vec![
                Span::styled(format!("{kind_tag} "), node_style.patch(bg)),
                Span::styled(
                    label,
                    bg.fg(if is_sel { C_FG() } else { C_FG2() })
                        .add_modifier(if is_sel {
                            Modifier::BOLD
                        } else {
                            Modifier::empty()
                        }),
                ),
                Span::styled(format!(" {score_bar}"), bg.fg(score_color(node.score))),
            ]))
        })
        .collect();

    let title = format!(" {} Nodes ", snap.node_ids.len());
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER()))
            .title(Span::styled(
                title,
                Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
            )),
    );
    f.render_widget(list, area);
}

// ─── Neighborhood view (center, default mode) ─────────────────────────────────

// ─── Adjacency view (tabular neighbors) ──────────────────────────────────────

pub fn draw_adjacency(f: &mut Frame, app: &App, area: Rect) {
    let engine = &app.core.operator_graph;
    let selected = app.graph_ui.selected_node;

    let header = Row::new(vec![
        Cell::from("Dir").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("Edge").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("Node").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("Hits").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("Score").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Cell::from("Last").style(Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
    ])
    .style(Style::default().bg(C_BG2()))
    .height(1);

    let rows: Vec<Row> = if let Some(node_id) = selected {
        let scroll = app.graph_ui.neighbor_scroll;
        let mut all_rows = Vec::new();

        for &eid in engine.out_edges(node_id) {
            if let Some(edge) = engine.get_edge(eid) {
                if let Some(nb) = engine.get_node(edge.dst) {
                    all_rows.push(("→", edge, nb));
                }
            }
        }
        for &eid in engine.in_edges(node_id) {
            if let Some(edge) = engine.get_edge(eid) {
                if let Some(nb) = engine.get_node(edge.src) {
                    all_rows.push(("←", edge, nb));
                }
            }
        }

        all_rows
            .iter()
            .skip(scroll)
            .take(area.height.saturating_sub(3) as usize)
            .map(|(dir, edge, nb)| {
                Row::new(vec![
                    Cell::from(*dir).style(Style::default().fg(if *dir == "→" {
                        C_GREEN()
                    } else {
                        C_CYAN()
                    })),
                    Cell::from(truncate(&edge.kind.to_string(), 20))
                        .style(Style::default().fg(C_YELLOW())),
                    Cell::from(truncate(&nb.label, 24)).style(node_kind_style(nb.kind())),
                    Cell::from(edge.hit_count.to_string()).style(Style::default().fg(C_FG2())),
                    Cell::from(format!("{:.2}", nb.score))
                        .style(Style::default().fg(score_color(nb.score))),
                    Cell::from(format_ts(edge.last_seen)).style(Style::default().fg(C_FG3())),
                ])
            })
            .collect()
    } else {
        vec![]
    };

    let title = selected
        .and_then(|id| engine.get_node(id))
        .map(|n| format!(" Adjacency: {} ", n.label))
        .unwrap_or_else(|| " Adjacency (no selection) ".into());

    let table = Table::new(
        rows,
        [
            Constraint::Length(3),
            Constraint::Length(20),
            Constraint::Min(20),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(9),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER()))
            .title(Span::styled(
                title,
                Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
            )),
    )
    .style(Style::default().bg(C_BG()));
    f.render_widget(table, area);
}

// ─── Paths view ───────────────────────────────────────────────────────────────

pub fn draw_paths(f: &mut Frame, app: &App, area: Rect) {
    let paths = &app.core.operator_graph.paths;
    let scroll = app.graph_ui.list_scroll;

    let items: Vec<ListItem> = paths
        .iter()
        .skip(scroll)
        .take(area.height.saturating_sub(2) as usize)
        .enumerate()
        .map(|(i, path)| {
            let is_sel = app.graph_ui.path_selected == i + scroll;
            let bg = if is_sel {
                Style::default().bg(C_SEL_BG())
            } else {
                Style::default()
            };
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(
                        format!("{} ", path.kind),
                        Style::default()
                            .fg(C_CYAN())
                            .patch(bg)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!(
                            "score:{:.2}  {}n {}e",
                            path.score,
                            path.nodes.len(),
                            path.edges.len()
                        ),
                        Style::default().fg(score_color(path.score)).patch(bg),
                    ),
                ]),
                Line::from(vec![Span::styled(
                    format!(
                        "  {}",
                        truncate(&path.summary, (area.width as usize).saturating_sub(4))
                    ),
                    Style::default().fg(C_FG2()).patch(bg),
                )]),
                Line::from(vec![Span::styled(
                    format!(
                        "  ↳ {}",
                        truncate(&path.why, (area.width as usize).saturating_sub(6))
                    ),
                    Style::default().fg(C_FG3()).patch(bg),
                )]),
            ])
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER()))
            .title(Span::styled(
                format!(" {} Attack Paths ", paths.len()),
                Style::default().fg(C_RED()).add_modifier(Modifier::BOLD),
            )),
    );
    f.render_widget(list, area);
}

// ─── Clusters view ────────────────────────────────────────────────────────────

pub fn draw_clusters(f: &mut Frame, app: &App, area: Rect) {
    let clusters = &app.core.operator_graph.clusters;
    let scroll = app.graph_ui.list_scroll;

    let items: Vec<ListItem> = clusters
        .iter()
        .skip(scroll)
        .take(area.height.saturating_sub(2) as usize)
        .enumerate()
        .map(|(i, c)| {
            let is_sel = app.graph_ui.cluster_selected == i + scroll;
            let bg = if is_sel {
                Style::default().bg(C_SEL_BG())
            } else {
                Style::default()
            };
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(
                        format!("[{}] ", c.kind),
                        Style::default()
                            .fg(C_YELLOW())
                            .patch(bg)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        truncate(&c.label, 28),
                        Style::default().fg(C_CYAN()).patch(bg),
                    ),
                    Span::styled(
                        format!("  {:.2}", c.score),
                        Style::default().fg(score_color(c.score)).patch(bg),
                    ),
                ]),
                Line::from(Span::styled(
                    format!(
                        "  {} ({} members)",
                        truncate(&c.summary, 50),
                        c.members.len()
                    ),
                    Style::default().fg(C_FG2()).patch(bg),
                )),
            ])
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER()))
            .title(Span::styled(
                format!(" {} Clusters ", clusters.len()),
                Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
            )),
    );
    f.render_widget(list, area);
}

// ─── Evidence view ────────────────────────────────────────────────────────────

pub fn draw_evidence(f: &mut Frame, app: &App, area: Rect) {
    let engine = &app.core.operator_graph;
    let mut lines: Vec<Line> = Vec::new();

    if let Some(node_id) = app.graph_ui.selected_node {
        if let Some(node) = engine.get_node(node_id) {
            lines.push(Line::from(vec![
                Span::styled("Node: ", Style::default().fg(C_FG3())),
                Span::styled(
                    node.label.clone(),
                    Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(Span::styled(
                format!("{} evidence refs", node.evidence.len()),
                Style::default().fg(C_FG3()),
            )));
            lines.push(Line::raw(""));

            let scroll = app.graph_ui.evidence_scroll;
            for ev in node
                .evidence
                .iter()
                .skip(scroll)
                .take(area.height.saturating_sub(6) as usize)
            {
                lines.push(Line::from(vec![
                    Span::styled("  • ", Style::default().fg(C_YELLOW())),
                    Span::styled(ev.to_string(), Style::default().fg(C_FG2())),
                ]));
            }
        }
    } else {
        lines.push(Line::from(Span::styled(
            "  Select a node to view its evidence refs.",
            Style::default().fg(C_FG3()),
        )));
    }

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER()))
                .title(Span::styled(
                    " Evidence ",
                    Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
                )),
        )
        .style(Style::default().bg(C_BG()))
        .wrap(Wrap { trim: false });
    f.render_widget(panel, area);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn node_kind_style(kind: GraphNodeKind) -> Style {
    match kind {
        GraphNodeKind::Host => Style::default().fg(C_CYAN()),
        GraphNodeKind::Service => Style::default().fg(C_GREEN()),
        GraphNodeKind::Flow => Style::default().fg(ratatui::style::Color::Blue),
        GraphNodeKind::Credential => Style::default().fg(C_RED()).add_modifier(Modifier::BOLD),
        GraphNodeKind::Certificate => Style::default().fg(C_YELLOW()),
        GraphNodeKind::IOC => Style::default().fg(C_RED()),
        GraphNodeKind::Alert => Style::default().fg(C_RED()).add_modifier(Modifier::BOLD),
        GraphNodeKind::FileObject => Style::default().fg(ratatui::style::Color::Magenta),
        GraphNodeKind::RuleHit => Style::default().fg(C_RED()),
        _ => Style::default().fg(C_FG2()),
    }
}

fn score_color(score: f32) -> ratatui::style::Color {
    if score >= 0.75 {
        C_RED()
    } else if score >= 0.45 {
        ratatui::style::Color::Yellow
    } else {
        C_GREEN()
    }
}

fn score_to_bar(score: f32) -> &'static str {
    if score >= 0.85 {
        "█████"
    } else if score >= 0.65 {
        "████░"
    } else if score >= 0.40 {
        "███░░"
    } else if score >= 0.15 {
        "██░░░"
    } else {
        "█░░░░"
    }
}

fn format_ts(ts: f64) -> String {
    let secs = ts as u64;
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
    t.push('…');
    t
}

fn wrap_text(s: &str, width: usize) -> Vec<&str> {
    if width == 0 {
        return vec![s];
    }
    s.split_whitespace()
        .collect::<Vec<_>>()
        .chunks(8)
        .map(|ch| {
            // Rough split by words — fine for short score_why strings
            ch.join(" ")
        })
        .collect::<Vec<_>>()
        .iter()
        .flat_map(|chunk| {
            // Return the chunk as a slice of s -- just take lines
            chunk
                .split('\n')
                .collect::<Vec<_>>()
                .into_iter()
                .map(|_l| s)
                .collect::<Vec<_>>()
        })
        .take(4)
        .collect()
}

mod detail;
pub use detail::draw_detail_panel;

mod neighborhood;
pub use neighborhood::draw_neighborhood;
