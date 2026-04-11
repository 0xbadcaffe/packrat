//! Operator Graph tab — keyboard-first engagement map explorer.
//!
//! Layout:
//!   ┌─ Node List ─┬─────── Focus View ──────────┬─ Detail Panel ─┐
//!   │ (scrollable)│  Neighborhood / Paths /      │ Kind / Score / │
//!   │ filterable  │  Clusters / Evidence         │ Why / Evidence │
//!   └─────────────┴──────────────────────────────┴────────────────┘
//!   [ Pivot bar / status ]

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph},
};
use crate::app::App;
use crate::analysis::operator_graph::GraphUiModeState;
use crate::ui::theme::*;
use super::graph_panels;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  // mode/filter bar
            Constraint::Min(0),     // main content
            Constraint::Length(2),  // pivot/status bar
        ])
        .split(area);

    draw_mode_bar(f, app, chunks[0]);

    let content = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(30),  // node list
            Constraint::Min(0),      // focus view
            Constraint::Length(38),  // detail panel
        ])
        .split(chunks[1]);

    graph_panels::draw_node_list(f, app, content[0]);

    match &app.graph_ui.mode {
        GraphUiModeState::Neighborhood => graph_panels::draw_neighborhood(f, app, content[1]),
        GraphUiModeState::Adjacency    => graph_panels::draw_adjacency(f, app, content[1]),
        GraphUiModeState::Paths        => graph_panels::draw_paths(f, app, content[1]),
        GraphUiModeState::Clusters     => graph_panels::draw_clusters(f, app, content[1]),
        GraphUiModeState::Evidence     => graph_panels::draw_evidence(f, app, content[1]),
    }

    graph_panels::draw_detail_panel(f, app, content[2]);
    draw_pivot_bar(f, app, chunks[2]);
}

fn draw_mode_bar(f: &mut Frame, app: &App, area: Rect) {
    let modes = ["Neighborhood", "Adjacency", "Paths", "Clusters", "Evidence"];
    let current = app.graph_ui.mode.label();

    let mut spans: Vec<Span> = Vec::new();
    spans.push(Span::styled(" Graph: ", Style::default().fg(C_FG3)));

    for m in &modes {
        let selected = *m == current;
        let style = if selected {
            Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            Style::default().fg(C_FG2)
        };
        spans.push(Span::styled(format!(" {m} "), style));
        spans.push(Span::styled("│", Style::default().fg(C_BORDER)));
    }

    let search = if app.graph_ui.searching {
        format!(" /{}_", app.graph_ui.search)
    } else if !app.graph_ui.search.is_empty() {
        format!(" /{}", app.graph_ui.search)
    } else {
        format!("  {} nodes  {} edges", app.operator_graph.node_count(), app.operator_graph.edge_count())
    };
    spans.push(Span::styled(search, Style::default().fg(C_YELLOW)));

    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(C_BG2)),
        area,
    );
}

fn draw_pivot_bar(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);

    // Top: pivot suggestions for selected node
    let pivot_line = if let Some(node_id) = app.graph_ui.selected_node {
        if !app.operator_graph.pivots.is_empty()
            && app.operator_graph.pivots_for == Some(node_id)
        {
            let pivots: Vec<String> = app.operator_graph.pivots.iter().take(4)
                .map(|p| format!("[{:.2}] {}", p.score, p.label))
                .collect();
            format!(" Pivots: {}", pivots.join("  │  "))
        } else {
            " [p] compute pivots for selected node".into()
        }
    } else {
        " Select a node to see pivots".into()
    };
    f.render_widget(
        Paragraph::new(pivot_line).style(Style::default().fg(C_CYAN).bg(C_BG2)),
        chunks[0],
    );

    // Bottom: controls
    let controls = match &app.graph_ui.mode {
        GraphUiModeState::Neighborhood => " [j/k] nodes  [Enter] focus  [Bksp] back  [Tab] mode  [p] pivots  [A] paths  [C] clusters  [/] search  [x] export  [q] quit",
        GraphUiModeState::Adjacency    => " [j/k] scroll adj  [Enter] focus neighbor  [Bksp] back  [Tab] mode  [q] quit",
        GraphUiModeState::Paths        => " [j/k] paths  [Enter] jump to first node  [Tab] mode  [q] quit",
        GraphUiModeState::Clusters     => " [j/k] clusters  [Enter] expand cluster  [Tab] mode  [q] quit",
        GraphUiModeState::Evidence     => " [j/k] scroll  [Tab] mode  [q] quit",
    };
    f.render_widget(
        Paragraph::new(controls).style(Style::default().fg(C_FG3).bg(C_BG2)),
        chunks[1],
    );
}
