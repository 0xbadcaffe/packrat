use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs},
};

use crate::app::App;
use crate::tabs::Tab;
use crate::ui::theme::*;

mod helpers;
mod help;
mod iface_picker;
mod tabs;
pub mod theme;

pub use helpers::fmt_bytes;

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // titlebar
            Constraint::Length(1), // filter bar
            Constraint::Length(2), // tabs
            Constraint::Min(0),    // workspace
            Constraint::Length(1), // statusbar
        ])
        .split(area);

    draw_titlebar(f, app, chunks[0]);
    draw_filterbar(f, app, chunks[1]);
    draw_tabs(f, app, chunks[2]);
    draw_workspace(f, app, chunks[3]);
    draw_statusbar(f, app, chunks[4]);

    if app.show_help {
        help::draw(f);
    }
}

fn draw_titlebar(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let cap_str = if app.capturing { "● capturing" } else { "○ idle" };
    let cap_color = if app.capturing { C_GREEN } else { C_FG3 };
    let rec_span = if app.recording {
        Span::styled(format!("  ◉ recording → {}", app.pcap_path), Style::default().fg(C_RED).add_modifier(Modifier::BOLD))
    } else {
        Span::raw("")
    };
    let line = Line::from(vec![
        Span::styled(" packrat ", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Span::styled("─ packet analyzer  ", Style::default().fg(C_FG3)),
        Span::styled(cap_str, Style::default().fg(cap_color)),
        Span::styled(
            format!("  iface: {}  {} pkts  {} total",
                app.selected_iface, app.packets.len(), app.packet_counter),
            Style::default().fg(C_FG3),
        ),
        rec_span,
    ]);
    f.render_widget(Paragraph::new(line).style(Style::default().bg(C_BG2)), area);
}

fn draw_filterbar(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let filter_display = if app.filter.active {
        format!("{}_", app.filter.input)
    } else if app.filter.input.is_empty() {
        "<press / to filter>".into()
    } else {
        app.filter.input.clone()
    };
    let filter_color = if app.filter.active { C_CYAN }
        else if app.filter.input.is_empty() { C_FG3 }
        else { C_YELLOW };

    let line = Line::from(vec![
        Span::styled(" Display filter: ", Style::default().fg(C_FG2)),
        Span::styled(filter_display, Style::default().fg(filter_color)),
        Span::styled(
            "  [Space] cap  [C] clear  [/] filter  [i] iface  [w] record  [h] help  [q] quit",
            Style::default().fg(C_FG3),
        ),
    ]);
    f.render_widget(Paragraph::new(line).style(Style::default().bg(C_BG2)), area);
}

fn draw_tabs(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let titles = vec![
        Line::from(vec![Span::styled("1 ", Style::default().fg(C_YELLOW)), Span::raw("Packets")]),
        Line::from(vec![Span::styled("2 ", Style::default().fg(C_YELLOW)), Span::raw("Analysis")]),
        Line::from(vec![Span::styled("3 ", Style::default().fg(C_YELLOW)), Span::raw("Strings")]),
        Line::from(vec![Span::styled("4 ", Style::default().fg(C_YELLOW)), Span::raw("Dynamic")]),
        Line::from(vec![Span::styled("5 ", Style::default().fg(C_YELLOW)), Span::raw("Visualize")]),
        Line::from(vec![Span::styled("6 ", Style::default().fg(C_YELLOW)), Span::raw("Topology")]),
        Line::from(vec![Span::styled("7 ", Style::default().fg(C_YELLOW)), Span::raw("Flows")]),
    ];
    let tabs = Tabs::new(titles)
        .select(app.active_tab.index())
        .style(Style::default().fg(C_FG2).bg(C_BG2))
        .highlight_style(Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD))
        .divider("│")
        .block(Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(C_BORDER)));
    f.render_widget(tabs, area);
}

fn draw_workspace(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    if app.picking_iface {
        iface_picker::draw(f, app, area);
        return;
    }
    match app.active_tab {
        Tab::Packets   => tabs::packets::draw(f, app, area),
        Tab::Analysis  => tabs::analysis::draw(f, app, area),
        Tab::Strings   => tabs::strings::draw(f, app, area),
        Tab::Dynamic   => tabs::dynamic::draw(f, app, area),
        Tab::Visualize => tabs::visualize::draw(f, app, area),
        Tab::Topology  => tabs::topology::draw(f, app, area),
        Tab::Flows     => tabs::flows::draw(f, app, area),
    }
}

fn draw_statusbar(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let cap_indicator = if app.capturing {
        Span::styled("● LIVE ", Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD))
    } else {
        Span::styled("○ IDLE ", Style::default().fg(C_FG3))
    };
    let rec_indicator = if app.recording {
        Span::styled("◉ REC ", Style::default().fg(C_RED).add_modifier(Modifier::BOLD))
    } else {
        Span::raw("")
    };

    let line = Line::from(vec![
        Span::styled(" ", Style::default()),
        cap_indicator,
        rec_indicator,
        Span::styled("│ ", Style::default().fg(C_FG3)),
        Span::styled(format!("pkts:{} ", app.filtered.len()), Style::default().fg(C_FG2)),
        Span::styled(format!("total:{} ", app.packets.len()), Style::default().fg(C_FG2)),
        Span::styled(format!("bytes:{} ", fmt_bytes(app.total_bytes)), Style::default().fg(C_FG2)),
        Span::styled(format!("rate:{}/s ", app.current_rate()), Style::default().fg(C_GREEN)),
        Span::styled("│ ", Style::default().fg(C_FG3)),
        Span::styled(
            "j/k:nav  g/G:top/bot  Space:cap  /:filter  i:iface  w:record  h:help  1-7:tabs  q:quit",
            Style::default().fg(C_FG3),
        ),
    ]);
    f.render_widget(Paragraph::new(line).style(Style::default().bg(C_BG2)), area);
}
