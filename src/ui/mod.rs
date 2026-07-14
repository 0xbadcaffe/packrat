use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Tabs, Wrap},
};

use crate::app::App;
use crate::tabs::{Tab, Workspace};
use crate::ui::theme::*;

pub mod autopsy_overlay;
mod helpers;
mod help;
mod iface_picker;
mod incident_overlay;
pub mod project_manager;
mod search_overlay;
mod tabs;
pub mod theme;
mod theme_picker;
mod view_menu;

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

    if let Some(overlay) = &app.stream_overlay {
        draw_stream_overlay(f, overlay);
    }

    if let Some(comparison) = &app.packet_comparison {
        draw_packet_comparison(f, comparison);
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

    if app.settings_open {
        draw_settings_overlay(f, app);
    }

    if app.theme_picker_open {
        theme_picker::draw(f, app);
    }

    if app.view_menu_open {
        view_menu::draw(f, app);
    }

    if app.alert_overlay_open {
        incident_overlay::draw(f, app);
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
        "<press / for packet inspection filter: tcp, ip.src==x, dns and port==53>".into()
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
    let workspace_tabs: Vec<Line> = (0..Workspace::COUNT).map(|index| {
        let workspace = Workspace::from_index(index);
        Line::from(vec![
            Span::styled(format!("{} ", index + 1), Style::default().fg(C_YELLOW())),
            Span::raw(workspace.label()),
        ])
    }).collect();
    let active_workspace = app.active_tab.workspace();
    let tabs = Tabs::new(workspace_tabs)
        .select(active_workspace.index())
        .style(Style::default().fg(C_FG2()).bg(C_BG2()))
        .highlight_style(Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD))
        .divider("│")
        .block(Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(C_BORDER()))
            .title(Span::styled(
                format!(" {}  [Tab/F2 views] ", app.active_tab.label()),
                Style::default().fg(C_FG2()),
            )));
    f.render_widget(tabs, area);
}

fn draw_workspace(f: &mut Frame, app: &App, area: Rect) {
    if app.picking_iface {
        iface_picker::draw(f, app, area);
        return;
    }
    match app.active_tab {
        Tab::Packets     => tabs::packets::draw(f, app, area),
        Tab::Investigate => tabs::investigate::draw(f, app, area),
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
        Tab::Settings      => tabs::settings::draw(f, app, area),
    }
}

fn draw_settings_overlay(f: &mut Frame, app: &App) {
    let area = f.area();
    let width = area.width.saturating_sub(6).min(96);
    let height = area.height.saturating_sub(4).min(26);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    if popup.width == 0 || popup.height == 0 { return; }
    f.render_widget(Clear, popup);
    tabs::settings::draw(f, app, popup);
}

fn draw_stream_overlay(f: &mut Frame, overlay: &crate::analysis::stream::StreamOverlayState) {
    let area = f.area();
    let popup = Rect {
        x: area.x + 4,
        y: area.y + 2,
        width: area.width.saturating_sub(8),
        height: area.height.saturating_sub(4),
    };
    f.render_widget(Clear, popup);

    let active_segment = overlay.matches.get(overlay.selected_match).map(|matched| matched.segment_index);
    let mut lines: Vec<Line> = vec![Line::from(if overlay.searching {
        format!("Search: {}_", overlay.search_query)
    } else if overlay.search_query.is_empty() {
        "Search: / type query   e export".into()
    } else {
        format!("Search: {}   match {}/{}   n/N navigate   e export", overlay.search_query, overlay.selected_match + 1, overlay.matches.len())
    })];
    for (index, (is_init, bytes)) in overlay.segments.iter().take(50).enumerate() {
        let color = if *is_init { C_CYAN() } else { C_GREEN() };
        let direction = if *is_init { "\u{2192}" } else { "\u{2190}" };
        let text: String = bytes.iter().take(200).map(|&b| {
            if b >= 32 && b < 127 { b as char } else { '.' }
        }).collect();
        let style = if active_segment == Some(index) {
            Style::default().fg(C_BG()).bg(C_YELLOW()).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(color)
        };
        lines.push(Line::from(vec![Span::styled(format!("{} ", direction), style), Span::styled(text, style)]));
    }

    let p = Paragraph::new(lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(C_CYAN()))
            .title(Span::styled(
                format!(" Follow Stream: {}  [Esc close] ", overlay.title),
                Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
            )))
        .style(Style::default().bg(C_BG2()))
        .wrap(Wrap { trim: false });
    f.render_widget(p, popup);
}

fn draw_packet_comparison(f: &mut Frame, comparison: &crate::analysis::packet_compare::PacketComparison) {
    use crate::analysis::packet_compare::FieldDifferenceKind;

    let area = f.area();
    let popup = Rect {
        x: area.x + 4,
        y: area.y + 2,
        width: area.width.saturating_sub(8),
        height: area.height.saturating_sub(4),
    };
    f.render_widget(Clear, popup);
    let byte_summary = comparison.first_byte_difference
        .map(|offset| format!("First byte difference: 0x{offset:04x}"))
        .unwrap_or_else(|| "Captured bytes are identical".into());
    let mut lines = vec![
        Line::from(format!("Lengths: {} vs {} bytes", comparison.left_length, comparison.right_length)),
        Line::from(byte_summary),
        Line::raw(""),
    ];
    for difference in comparison.field_differences.iter().take(popup.height.saturating_sub(7) as usize) {
        let marker = match difference.kind {
            FieldDifferenceKind::Changed => "~",
            FieldDifferenceKind::LeftOnly => "-",
            FieldDifferenceKind::RightOnly => "+",
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{marker} {:<24} ", difference.path), Style::default().fg(C_CYAN())),
            Span::styled(difference.left.as_deref().unwrap_or("<absent>"), Style::default().fg(C_YELLOW())),
            Span::raw(" -> "),
            Span::styled(difference.right.as_deref().unwrap_or("<absent>"), Style::default().fg(C_GREEN())),
        ]));
    }
    let widget = Paragraph::new(lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_CYAN()))
            .title(Span::styled(
                format!(" Compare Packet #{} -> #{}  [Esc/= close] ", comparison.left_no, comparison.right_no),
                Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
            )))
        .style(Style::default().bg(C_BG2()))
        .wrap(Wrap { trim: false });
    f.render_widget(widget, popup);
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
            "1-5:modes  Tab/F2:views  m:mark  Enter:investigate  [/]:screen  ,:settings  ?:search  h:help  q:quit",
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
