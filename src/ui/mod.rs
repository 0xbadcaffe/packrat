use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Tabs, Wrap},
};

use crate::app::App;
use crate::tabs::Tab;
use crate::ui::theme::*;

pub mod autopsy_overlay;
mod helpers;
mod help;
mod iface_picker;
pub mod project_manager;
mod search_overlay;
mod tabs;
pub mod theme;
mod theme_picker;

pub use helpers::fmt_bytes;

pub fn draw(f: &mut Frame, app: &App) {
    // Apply the active theme before rendering any widget.
    theme::set_theme(theme::palette_by_name(&app.selected_theme_name));

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

    if let Some((title, segments)) = &app.stream_overlay {
        draw_stream_overlay(f, title, segments);
    }

    if app.search_open {
        search_overlay::draw(f, app);
    }

    if app.autopsy_state.is_some() {
        autopsy_overlay::draw(f, app);
    }

    if app.pcap_import_editing {
        draw_pcap_import_overlay(f, app);
    }

    if app.project_manager_open {
        project_manager::draw(f, app);
    }

    if app.theme_picker_open {
        theme_picker::draw(f, app);
    }
}

fn draw_titlebar(f: &mut Frame, app: &App, area: Rect) {
    let cap_str = if app.capturing { "● capturing" } else { "○ idle" };
    let cap_color = if app.capturing { C_GREEN() } else { C_FG3() };
    let rec_span = if app.recording {
        Span::styled(
            format!("  ◉ recording → {}", app.pcap_path),
            Style::default().fg(C_RED()).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::raw("")
    };

    // Security alert badge
    let sec_count = app.security.alert_count() + app.credentials.len();
    let sec_span = if sec_count > 0 {
        Span::styled(
            format!("  ⚠ {} alerts", sec_count),
            Style::default().fg(C_RED()).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::raw("")
    };

    // IOC hit badge
    let ioc_hits = app.ioc_engine.hit_count();
    let ioc_span = if ioc_hits > 0 {
        Span::styled(
            format!("  ☢ {} IOC", ioc_hits),
            Style::default().fg(C_ORANGE()).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::raw("")
    };

    // Rule hit badge
    let rule_hits = app.rule_engine.hits.len();
    let rule_span = if rule_hits > 0 {
        Span::styled(
            format!("  ⚡ {} rules", rule_hits),
            Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::raw("")
    };

    // Project name badge
    let project_span = if let Some(ref name) = app.current_project_name {
        let dirty = if app.project_dirty { "*" } else { "" };
        Span::styled(
            format!("  [{dirty}{name}]"),
            Style::default().fg(if app.project_dirty { C_ORANGE() } else { C_CYAN() }),
        )
    } else {
        Span::raw("")
    };

    let line = Line::from(vec![
        Span::styled(" packrat ", Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Span::styled("─ packet analyzer  ", Style::default().fg(C_FG3())),
        Span::styled(cap_str, Style::default().fg(cap_color)),
        Span::styled(
            format!("  iface: {}  {} pkts  {} total",
                app.selected_iface, app.packets.len(), app.packet_counter),
            Style::default().fg(C_FG3()),
        ),
        rec_span,
        project_span,
        sec_span,
        ioc_span,
        rule_span,
    ]);
    f.render_widget(Paragraph::new(line).style(Style::default().bg(C_BG2())), area);
}

fn draw_filterbar(f: &mut Frame, app: &App, area: Rect) {
    let has_error = app.display_filter.has_error();
    let filter_display = if app.filter.active {
        format!("{}_", app.filter.input)
    } else if app.filter.input.is_empty() {
        "<press / for Wireshark-style filter: tcp, ip.src==x, dns and port==53>".into()
    } else {
        app.filter.input.clone()
    };
    let filter_color = if has_error { C_RED() }
        else if app.filter.active { C_CYAN() }
        else if app.filter.input.is_empty() { C_FG3() }
        else { C_YELLOW() };

    let error_span = if let Some(ref e) = app.display_filter.error {
        Span::styled(format!("  ✗ {e}"), Style::default().fg(C_RED()))
    } else if !app.filter.input.is_empty() && !has_error {
        Span::styled(
            format!("  ✓ {} matched", app.filtered.len()),
            Style::default().fg(C_GREEN()),
        )
    } else {
        Span::styled(
            "  [L] load pcap  [B] baseline  [?] search  [h] help",
            Style::default().fg(C_FG3()),
        )
    };

    let line = Line::from(vec![
        Span::styled(" Filter: ", Style::default().fg(C_FG2())),
        Span::styled(filter_display, Style::default().fg(filter_color)),
        error_span,
    ]);
    f.render_widget(Paragraph::new(line).style(Style::default().bg(C_BG2())), area);
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    // All 18 tabs: (shortcut_key, label)
    const ALL: &[(&str, &str)] = &[
        ("1 ", "Packets"),  ("2 ", "Analysis"), ("3 ", "Strings"),
        ("4 ", "Dynamic"),  ("5 ", "Visualize"),("6 ", "Flows"),
        ("7 ", "Craft"),    ("8 ", "Trace"),    ("9 ", "Security"),
        ("0 ", "Scanner"),  ("H ", "Hosts"),    ("N ", "Notebook"),
        ("T ", "TLS"),      ("O ", "Objects"),  ("R ", "Rules"),
        ("W ", "Workbench"),("G ", "Graph"),    ("D ", "Diff"),
    ];

    let active = app.active_tab.index();

    // Each tab renders as " {key}{label} " (2 padding) plus "│" divider between tabs.
    // Width = key.len + label.len + 2 (padding) + 1 (divider) — except the last has no divider.
    let widths: Vec<u16> = ALL.iter().enumerate().map(|(i, (k, l))| {
        let text = k.len() + l.len() + 2; // " key label "
        (text + if i + 1 < ALL.len() { 1 } else { 0 }) as u16
    }).collect();

    let avail = area.width;

    // Find the smallest `start` such that the active tab falls within the visible window.
    // We prefer to show as many tabs as possible starting from `start`.
    let mut start = 0usize;
    loop {
        // How many tabs fit from `start`?
        let mut used = 0u16;
        let mut end = start;
        while end < ALL.len() {
            let w = widths[end];
            if used + w > avail { break; }
            used += w;
            end += 1;
        }
        if active < end || start >= active {
            break; // active is visible
        }
        start += 1;
    }

    // Collect the visible slice and build Line items for the Tabs widget.
    let mut visible: Vec<Line> = Vec::new();
    let mut used = 0u16;
    let mut end = start;
    while end < ALL.len() {
        if used + widths[end] > avail { break; }
        used += widths[end];
        let (key, label) = ALL[end];
        visible.push(Line::from(vec![
            Span::styled(key,   Style::default().fg(C_YELLOW())),
            Span::raw(label),
        ]));
        end += 1;
    }

    // If we scrolled, show a left-overflow indicator in the first tab slot.
    if start > 0 {
        if let Some(first) = visible.first_mut() {
            *first = Line::from(vec![
                Span::styled("◀ ", Style::default().fg(C_FG3())),
                Span::raw(ALL[start].1),
            ]);
        }
    }
    // If there are hidden tabs to the right, show a right-overflow indicator.
    if end < ALL.len() {
        if let Some(last) = visible.last_mut() {
            *last = Line::from(Span::styled(" ▶", Style::default().fg(C_FG3())));
        }
    }

    let tabs = Tabs::new(visible)
        .select(active.saturating_sub(start))
        .style(Style::default().fg(C_FG2()).bg(C_BG2()))
        .highlight_style(Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD))
        .divider("│")
        .block(Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(C_BORDER())));
    f.render_widget(tabs, area);
}

fn draw_workspace(f: &mut Frame, app: &App, area: Rect) {
    if app.picking_iface {
        iface_picker::draw(f, app, area);
        return;
    }
    match app.active_tab {
        Tab::Packets     => tabs::packets::draw(f, app, area),
        Tab::Analysis    => tabs::analysis::draw(f, app, area),
        Tab::Strings     => tabs::strings::draw(f, app, area),
        Tab::Dynamic     => tabs::dynamic::draw(f, app, area),
        Tab::Visualize   => tabs::visualize::draw(f, app, area),
        Tab::Flows       => tabs::flows::draw(f, app, area),
        Tab::Craft       => tabs::craft::draw(f, app, area),
        Tab::Traceroute  => tabs::traceroute::draw(f, app, area),
        Tab::Security    => tabs::security::draw(f, app, area),
        Tab::Scanner     => tabs::scanner::draw(f, app, area),
        Tab::Hosts       => tabs::hosts::draw(f, app, area),
        Tab::Notebook    => tabs::notebook::draw(f, app, area),
        Tab::TlsAnalysis => tabs::tls_tab::draw(f, app, area),
        Tab::Objects     => tabs::objects::draw(f, app, area),
        Tab::Rules       => tabs::rules::draw(f, app, area),
        Tab::Workbench     => tabs::workbench::draw(f, app, area),
        Tab::OperatorGraph => tabs::operator_graph::draw(f, app, area),
        Tab::Diff          => tabs::diff::draw(f, app, area),
    }
}

fn draw_stream_overlay(f: &mut Frame, title: &str, segments: &[(bool, Vec<u8>)]) {
    let area = f.area();
    let popup = Rect {
        x: area.x + 4,
        y: area.y + 2,
        width: area.width.saturating_sub(8),
        height: area.height.saturating_sub(4),
    };
    f.render_widget(Clear, popup);

    let mut lines: Vec<Line> = Vec::new();
    for (is_init, bytes) in segments.iter().take(50) {
        let color = if *is_init { C_CYAN() } else { C_GREEN() };
        let direction = if *is_init { "\u{2192}" } else { "\u{2190}" };
        let text: String = bytes.iter().take(200).map(|&b| {
            if b >= 32 && b < 127 { b as char } else { '.' }
        }).collect();
        lines.push(Line::from(vec![
            Span::styled(format!("{} ", direction), Style::default().fg(color)),
            Span::styled(text, Style::default().fg(color)),
        ]));
    }

    let p = Paragraph::new(lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(C_CYAN()))
            .title(Span::styled(
                format!(" Follow Stream: {}  [Esc to close] ", title),
                Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
            )))
        .style(Style::default().bg(C_BG2()))
        .wrap(Wrap { trim: false });
    f.render_widget(p, popup);
}

fn draw_statusbar(f: &mut Frame, app: &App, area: Rect) {
    let cap_indicator = if app.capturing {
        Span::styled("● LIVE ", Style::default().fg(C_GREEN()).add_modifier(Modifier::BOLD))
    } else {
        Span::styled("○ IDLE ", Style::default().fg(C_FG3()))
    };
    let rec_indicator = if app.recording {
        Span::styled("◉ REC ", Style::default().fg(C_RED()).add_modifier(Modifier::BOLD))
    } else {
        Span::raw("")
    };

    let lua_span = if let Some(msg) = &app.lua_reload_msg {
        Span::styled(format!("│ {} ", msg), Style::default().fg(C_CYAN()))
    } else if app.lua_plugins.plugin_count() > 0 {
        Span::styled(format!("│ Lua:{} ", app.lua_plugins.proto_count()), Style::default().fg(C_FG3()))
    } else {
        Span::raw("")
    };

    let sec_count = app.security.alert_count() + app.credentials.len();
    let sec_span = if sec_count > 0 {
        Span::styled(format!("│ ⚠ {} ", sec_count), Style::default().fg(C_RED()).add_modifier(Modifier::BOLD))
    } else {
        Span::raw("")
    };

    let hints = if let Some(ref msg) = app.status_msg {
        Span::styled(format!("│ {} ", msg), Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(
            "j/k:nav  ?:search  X:export  L:load  B:baseline  a:autopsy  Space:cap  h:help  q:quit",
            Style::default().fg(C_FG3()),
        )
    };

    let line = Line::from(vec![
        Span::styled(" ", Style::default()),
        cap_indicator,
        rec_indicator,
        Span::styled("│ ", Style::default().fg(C_FG3())),
        Span::styled(format!("pkts:{} ", app.filtered.len()), Style::default().fg(C_FG2())),
        Span::styled(format!("total:{} ", app.packets.len()), Style::default().fg(C_FG2())),
        Span::styled(format!("bytes:{} ", fmt_bytes(app.total_bytes)), Style::default().fg(C_FG2())),
        Span::styled(format!("rate:{}/s ", app.current_rate()), Style::default().fg(C_GREEN())),
        lua_span,
        sec_span,
        Span::styled("│ ", Style::default().fg(C_FG3())),
        hints,
    ]);
    f.render_widget(Paragraph::new(line).style(Style::default().bg(C_BG2())), area);
}

fn draw_pcap_import_overlay(f: &mut Frame, app: &App) {
    let area = f.area();
    let popup = Rect {
        x: area.width / 6,
        y: area.height / 2 - 2,
        width: area.width * 2 / 3,
        height: 5,
    };

    f.render_widget(Clear, popup);

    let content = Paragraph::new(vec![
        Line::raw(""),
        Line::from(vec![
            Span::styled("  Path: ", Style::default().fg(C_FG2())),
            Span::styled(
                format!("{}_", app.pcap_import_path),
                Style::default().fg(C_CYAN()),
            ),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled(
                "  [Enter] load   [Esc] cancel",
                Style::default().fg(C_FG3()),
            ),
        ]),
    ])
    .block(Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_YELLOW()))
        .title(Span::styled(
            " Load PCAP File (instant import) ",
            Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
        )))
    .style(Style::default().bg(C_BG2()));
    f.render_widget(content, popup);
}
