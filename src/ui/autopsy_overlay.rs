//! Protocol Autopsy overlay — full-screen per-packet dissection view.
//!
//! Triggered by pressing 'a' on a selected packet in the Packets tab.
//! Shows: protocol dissection tree | stream context (TCP reassembly if available).
//! [Esc] to close, [j/k] to scroll tree, [Tab] to switch panes.

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};
use crate::app::App;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();

    // Full-screen popup (leaving a 1-cell margin all around)
    let popup = Rect {
        x: area.x + 1,
        y: area.y + 1,
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(2),
    };
    f.render_widget(Clear, popup);

    let pkt = match app.selected_packet() {
        Some(p) => p,
        None => {
            let msg = Paragraph::new("No packet selected.")
                .block(Block::default().borders(Borders::ALL)
                    .border_style(Style::default().fg(C_CYAN()))
                    .title(" Protocol Autopsy  [Esc] close "))
                .style(Style::default().bg(C_BG()));
            f.render_widget(msg, popup);
            return;
        }
    };

    let title = format!(
        " Autopsy: #{} {} → {} [{}] {} bytes  [Esc] close  [Tab] pane  [j/k] scroll ",
        pkt.no, pkt.src, pkt.dst, pkt.protocol, pkt.length
    );

    let outer_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_CYAN()))
        .title(Span::styled(title, Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)));
    f.render_widget(outer_block, popup);

    // Inner area (inside border)
    let inner = Rect {
        x: popup.x + 1,
        y: popup.y + 1,
        width: popup.width.saturating_sub(2),
        height: popup.height.saturating_sub(2),
    };

    // Split: left = dissection tree (2/3), right = stream context (1/3)
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(2, 3), Constraint::Ratio(1, 3)])
        .split(inner);

    draw_tree_pane(f, app, panes[0]);
    draw_stream_pane(f, app, panes[1]);
}

// ─── Protocol dissection tree ─────────────────────────────────────────────────

fn draw_tree_pane(f: &mut Frame, app: &App, area: Rect) {
    let state = match &app.autopsy_state {
        Some(s) => s,
        None => return,
    };

    // Build tree rows
    let mut items: Vec<ListItem> = Vec::new();
    for section in &state.tree {
        // Section header
        items.push(ListItem::new(Line::from(vec![
            Span::styled("▼ ", Style::default().fg(C_CYAN())),
            Span::styled(section.title.clone(),
                Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD)),
        ])));
        // Fields
        for field in &section.fields {
            let color = match field.color {
                crate::net::packet::FieldColor::Cyan    => C_CYAN(),
                crate::net::packet::FieldColor::Green   => C_GREEN(),
                crate::net::packet::FieldColor::Yellow  => C_YELLOW(),
                crate::net::packet::FieldColor::Red     => C_RED(),
                crate::net::packet::FieldColor::Magenta => C_MAGENTA(),
                crate::net::packet::FieldColor::Orange  => C_ORANGE(),
                crate::net::packet::FieldColor::Default => C_FG2(),
            };
            items.push(ListItem::new(Line::from(vec![
                Span::styled("    ", Style::default()),
                Span::styled(format!("{:<22}", field.key), Style::default().fg(C_FG2())),
                Span::styled(field.val.clone(), Style::default().fg(color)),
            ])));
        }
        items.push(ListItem::new(Line::raw("")));
    }

    let scroll = state.tree_scroll;
    let visible: Vec<_> = items.into_iter().skip(scroll).collect();

    let is_active = state.active_pane == AutopsyPane::Tree;
    let border_color = if is_active { C_CYAN() } else { C_BORDER() };

    let list = List::new(visible)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(Span::styled(
                if is_active { " Protocol Tree [active] " } else { " Protocol Tree " },
                Style::default().fg(if is_active { C_CYAN() } else { C_FG3() })
                    .add_modifier(Modifier::BOLD),
            )))
        .style(Style::default().bg(C_BG()));
    f.render_widget(list, area);
}

// ─── Stream context pane ──────────────────────────────────────────────────────

fn draw_stream_pane(f: &mut Frame, app: &App, area: Rect) {
    let state = match &app.autopsy_state {
        Some(s) => s,
        None => return,
    };

    let is_active = state.active_pane == AutopsyPane::Stream;
    let border_color = if is_active { C_CYAN() } else { C_BORDER() };

    let mut lines: Vec<Line> = Vec::new();

    if state.stream_preview.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No stream data",
            Style::default().fg(C_FG3()),
        )));
        lines.push(Line::from(Span::styled(
            "  (TCP only, needs reassembly)",
            Style::default().fg(C_FG3()),
        )));
    } else {
        let scroll = state.stream_scroll;
        for (dir, text) in state.stream_preview.iter().skip(scroll).take(200) {
            let (arrow, color) = if *dir {
                ("\u{2192}", C_CYAN())   // →
            } else {
                ("\u{2190}", C_GREEN())  // ←
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{} ", arrow), Style::default().fg(color)),
                Span::styled(text.clone(), Style::default().fg(color)),
            ]));
        }
    }

    let p = Paragraph::new(lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(Span::styled(
                if is_active { " Stream Context [active] " } else { " Stream Context " },
                Style::default().fg(if is_active { C_CYAN() } else { C_FG3() })
                    .add_modifier(Modifier::BOLD),
            )))
        .style(Style::default().bg(C_BG()))
        .wrap(Wrap { trim: true });
    f.render_widget(p, area);
}

// ─── Autopsy state ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum AutopsyPane { Tree, Stream }

#[derive(Debug, Clone)]
pub struct AutopsyState {
    pub tree:           Vec<crate::net::packet::TreeSection>,
    pub tree_scroll:    usize,
    pub stream_preview: Vec<(bool, String)>,   // (from_client, text_line)
    pub stream_scroll:  usize,
    pub active_pane:    AutopsyPane,
}

impl AutopsyState {
    pub fn new(
        tree:           Vec<crate::net::packet::TreeSection>,
        stream_preview: Vec<(bool, String)>,
    ) -> Self {
        Self {
            tree,
            tree_scroll: 0,
            stream_preview,
            stream_scroll: 0,
            active_pane: AutopsyPane::Tree,
        }
    }
}
